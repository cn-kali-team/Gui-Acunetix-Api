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
        # print(request_info.data)
        # exit()
        new_responder = requests.get(url=self.api_url + "/task/new",
                                     headers={'Content-Type': 'application/json'}).json()
        if new_responder.get("success"):
            task_id = new_responder.get("taskid")
        else:
            task_id = None
        scheme, netloc, path, query, fragment = parse.urlsplit(target_url)
        sql_injection_url = scheme + "://" + netloc + request_info.path
        if request_info.data:
            for payload in payloads:
                data = parse.unquote(request_info.data).replace(payload, original)
                post_data = {'url': sql_injection_url, 'method': request_info.command, 'data': data,
                             'headers': request_info.headers, 'p': point, "isDba": True}
                set_responder = requests.post(url=self.api_url + "/option/{task_id}/set".format(task_id=task_id),
                                              data=json.dumps(post_data),
                                              headers={'Content-Type': 'application/json'}).json()
                start_responder = requests.post(url=self.api_url + "/scan/{task_id}/start".format(task_id=task_id),
                                                data=json.dumps(post_data),
                                                headers={'Content-Type': 'application/json'}).json()
        else:
            post_data = {'url': sql_injection_url, 'method': request_info.command,
                         'headers': request_info.headers, 'p': point, "isDba": True}
            set_responder = requests.post(url=self.api_url + "/option/{task_id}/set".format(task_id=task_id),
                                          data=json.dumps(post_data),
                                          headers={'Content-Type': 'application/json'}).json()
            start_responder = requests.post(url=self.api_url + "/scan/{task_id}/start".format(task_id=task_id),
                                            data=json.dumps(post_data),
                                            headers={'Content-Type': 'application/json'}).json()



    def list(self, gui):
        list_responder = requests.get(url=self.api_url + "/admin/list").json()
        gui.list_store_sql_injection.clear()
        for task_id in list_responder["tasks"].keys():
            data_json = self.data(task_id)
            status = self.status(task_id=task_id)
            option = self.option(task_id=task_id)

            if data_json["data"]:
                injection_type = []
                injection_payload = []
                url = data_json["data"][0]["value"].get("url")
                data = data_json["data"][0]["value"].get("data")
                dbms = data_json["data"][1]["value"][0].get("dbms")
                dbms_version = str(data_json["data"][1]["value"][0].get("dbms_version"))
                for key in data_json["data"][1]["value"][0]["data"].keys():
                    injection_type.append(data_json["data"][1]["value"][0]["data"][key].get("title"))
                    injection_payload.append(data_json["data"][1]["value"][0]["data"][key].get("payload"))
                gui.list_store_sql_injection.insert_before(None,
                                                           [self.api_url, task_id, status, url, data, dbms,
                                                            dbms_version,
                                                            str(injection_type), str(injection_payload)])
            else:
                gui.list_store_sql_injection.insert_before(None, [self.api_url, task_id, status,
                                                                  option.get("url"), option.get("data"), "未知",
                                                                  "未知", "未知", "未知"])

    def data(self, task_id: str):
        status_responder = requests.get(url=self.api_url + "/scan/{task_id}/data".format(task_id=task_id),
                                        headers={'Content-Type': 'application/json'}).json()
        return status_responder

    def del_task(self, task_id):
        requests.get(self.api_url + "/task/{task_id}/delete".format(task_id=task_id)).json()

    def status(self, task_id):
        responder = requests.get(self.api_url + "/scan/{task_id}/status".format(task_id=task_id)).json()
        return responder.get("status")

    def option(self, task_id):
        responder = requests.get(self.api_url + "/option/{task_id}/list".format(task_id=task_id)).json()
        return responder["options"]
