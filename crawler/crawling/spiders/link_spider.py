from __future__ import absolute_import
import scrapy

from scrapy.http import Request
from crawling.spiders.lxmlhtml import CustomLxmlLinkExtractor as LinkExtractor
from scrapy.conf import settings

from crawling.items import RawResponseItem
from crawling.spiders.redis_spider import RedisSpider

from scutils.stats_collector import StatsCollector

from scutils.log_factory import LogFactory
import socket
import time
import redis
import sys
from redis.exceptions import ConnectionError


class LinkSpider(RedisSpider):
    '''
    A spider that walks all links from the requested URL. This is
    the entrypoint for generic crawling.
    '''
    name = "link"

    def __init__(self, *args, **kwargs):
        super(LinkSpider, self).__init__(*args, **kwargs)

        settings = get_project_settings()
        self.redis_conn = redis.Redis(host=settings.get('REDIS_HOST'),
                                      port=settings.get('REDIS_PORT'),
                                      db=settings.get('REDIS_DB'))

        try:
            self.redis_conn.info()
            self.logger.debug("Connected to Redis in Spider")
        except ConnectionError:
            self.logger.error("Failed to connect to Redis in Spider")
            # plugin is essential to functionality
            sys.exit(1)

        self.temp_key = 'domain:stats:pages'

        self.counter = {}


    def parse(self, response):
        self._logger.info("crawled url {}".format(response.request.url))
        cur_depth = 0
        if 'curdepth' in response.meta:
            cur_depth = response.meta['curdepth']

        # capture raw response
        item = RawResponseItem()
        # populated from response.meta
        item['appid'] = response.meta['appid']
        item['crawlid'] = response.meta['crawlid']
        item['attrs'] = response.meta['attrs']

        # populated from raw HTTP response
        item["url"] = response.request.url
        item["response_url"] = response.url
        item["status_code"] = response.status
        item["status_msg"] = "OK"
        item["response_headers"] = self.reconstruct_headers(response)
        item["request_headers"] = response.request.headers
        item["body"] = response.body
        item["links"] = []

        if item['crawlid']  not in self.counter:
            key='{k:i}'.format(k=self.temp_key, i=item['crawlid'] ),
            self.counter[item['crawlid']] = StatsCollector.get_counter(edis_conn=self.redis_conn,
                            key=key,)

        self.counter[item['crawlid']].increment()

        # determine whether to continue spidering
        if cur_depth >= response.meta['maxdepth']:
            self._logger.info("Not spidering links in '{}' because" \
                " cur_depth={} >= maxdepth={}".format(
                                                      response.url,
                                                      cur_depth,
                                                      response.meta['maxdepth']))
        else:
            # we are spidering -- yield Request for each discovered link
            link_extractor = LinkExtractor(
                            allow_domains=response.meta['allowed_domains'],
                            allow=response.meta['allow_regex'],
                            deny=response.meta['deny_regex'],
                            deny_extensions=response.meta['deny_extensions'])

            for link in link_extractor.extract_links(response):
                # link that was discovered
                the_url = link.url
                the_url = the_url.replace('\n', '')
                item["links"].append({"url": the_url, "text": link.text, })
                req = Request(the_url, callback=self.parse)

                req.meta['priority'] = response.meta['priority'] - 10
                req.meta['curdepth'] = response.meta['curdepth'] + 1

                if 'useragent' in response.meta and \
                        response.meta['useragent'] is not None:
                    req.headers['User-Agent'] = response.meta['useragent']

                self._logger.debug("Trying to follow link '{}'".format(req.url))
                yield req

        # raw response has been processed, yield to item pipeline
        yield item
