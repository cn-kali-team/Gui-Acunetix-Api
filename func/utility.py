import io
import ast
from http.server import BaseHTTPRequestHandler
from html.parser import HTMLParser


def list_to_tag(lists):
    for tag in lists:
        if not (tag == "PerScheme" or tag[0:3] == "CWE" or tag == "verified"):
            return tag


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, raw_http_request):
        self.rfile = io.BytesIO(raw_http_request.encode())
        self.raw_requestline = self.rfile.readline()
        self.parse_request()

        self.headers = dict(self.headers)
        print(raw_http_request[raw_http_request.index("\r\n\r\n") + 4:].rstrip())
        # Data
        try:
            self.data = raw_http_request[raw_http_request.index("\r\n\r\n") + 4:].rstrip()
            print(self.data)
        except ValueError:
            self.data = None


class ClassParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.recording = 0
        self.data = []
        self.point = ""

    def handle_starttag(self, tag, attributes):
        if tag != 'span':
            return
        if self.recording:
            self.recording += 1
            return
        for name, value in attributes:
            if name == 'class' and value == 'bb-dark':
                break
        else:
            return
        self.recording = 1

    def feed_pro(self, data, point):
        self.point = point
        try:
            self.feed(data=data)
            return self.data
        finally:
            self.data = []

    def handle_endtag(self, tag):
        if tag == 'span' and self.recording:
            self.recording -= 1

    def handle_data(self, data):
        if self.recording and data != self.point:
            self.data.append(data)


def html_to_parser(html, point):
    dd_dark = ClassParser()
    value_list = dd_dark.feed_pro(ast.literal_eval(html).decode(), point)
    return str(value_list)


def html_to_original(html):
    original_txt = ast.literal_eval(html).decode()
    start = original_txt.find("Original value: <strong>")
    if start > 0:
        original_txt = original_txt[start+len("Original value: <strong>"):-len("</strong>")]
    else:
        original_txt = ""
    return original_txt
