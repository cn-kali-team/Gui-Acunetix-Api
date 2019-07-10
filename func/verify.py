import requests
import func.utility as util
import json
from urllib import parse


class SqlMapApi:
    def __init__(self, host, port, username=None, password=None):
        self.api_url = "http://{h}:{p}".format(h=host, p=port)
        self.username = username
        self.password = password

    def add(self, target_url: str, raw: str, payloads: list = None, point: str = None, original: str = None):
        # for payload in payloads:
        #     raw = parse.unquote(raw).replace(payload, original)
        request_info = util.HTTPRequest(raw_http_request=raw)
        # method: str, data: dict, headers: dict
        new_responder = requests.get(url=self.api_url + "/task/new",
                                     headers={'Content-Type': 'application/json'}).json()
        if new_responder.get("success"):
            task_id = new_responder.get("taskid")
        else:
            task_id = None
        scheme, netloc, path, query, fragment = parse.urlsplit(target_url)
        sql_injection_url = scheme + "://" + netloc + request_info.path

        post_data = {'url': sql_injection_url, 'method': request_info.command, 'data': request_info.data,
                     'headers': request_info.headers, 'p': point, "level": 5, "risk": 3, "isDba":True}
        set_responder = requests.post(url=self.api_url + "/option/{task_id}/set".format(task_id=task_id),
                                      data=json.dumps(post_data), headers={'Content-Type': 'application/json'}).json()
        start_responder = requests.post(url=self.api_url + "/scan/{task_id}/start".format(task_id=task_id),
                                        data=json.dumps(post_data), headers={'Content-Type': 'application/json'}).json()

    def list(self, gui):
        list_responder = requests.get(url=self.api_url + "/admin/list").json()
        gui.list_store_sql_injection.clear()
        for task_id in list_responder["tasks"].keys():
            data_json = self.data(task_id)
            if data_json["data"]:
                injection_type = []
                injection_payload = []
                url = data_json["data"][0]["value"].get("url")
                dbms = data_json["data"][1]["value"][0].get("dbms")
                dbms_version = str(data_json["data"][1]["value"][0].get("dbms_version"))
                for key in data_json["data"][1]["value"][0]["data"].keys():
                    injection_type.append(data_json["data"][1]["value"][0]["data"][key].get("title"))
                    injection_payload.append(data_json["data"][1]["value"][0]["data"][key].get("payload"))
                gui.list_store_sql_injection.insert_before(None, [self.api_url, task_id, url, dbms, dbms_version,
                                                                  str(injection_type), str(injection_payload)])
            else:
                gui.list_store_sql_injection.insert_before(None, [self.api_url, task_id, "url", "dbms", "dbms_version",
                                                                  "injection_type", "injection_payload"])

    def data(self, task_id: str):
        status_responder = requests.get(url=self.api_url + "/scan/{task_id}/data".format(task_id=task_id),
                                        headers={'Content-Type': 'application/json'}).json()
        return status_responder

    def del_task(self, task_id):
        requests.get(self.api_url + "/task/{task_id}/delete".format(task_id=task_id)).json()
