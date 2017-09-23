#!/bin/sh


cd /home/antosha/python/scrapy-cluster/crawler;

if ! /bin/ps aux |/bin/grep -v grep |/bin/grep 'scrapy runspider' -q
    then  /usr/bin/python /usr/local/bin/scrapy  runspider crawling/spiders/link_spider.py 2>&1 &
fi