#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import requests
import urllib3
import logging
import time
import func.utility as util

urllib3.disable_warnings()
rules = {
    "H": '11111111-1111-1111-1111-111111111112',  # High Risk Vulnerabilities
    "W": '11111111-1111-1111-1111-111111111115',  # Weak Passwords
    "C": '11111111-1111-1111-1111-111111111117',  # Crawl Only
    "X": '11111111-1111-1111-1111-111111111116',  # Cross-site Scripting Vulnerabilities
    "S": '11111111-1111-1111-1111-111111111113',  # SQL Injection Vulnerabilities
    "F": '11111111-1111-1111-1111-111111111111'  # Full Scan
}


class ScanApi:
    def __init__(self, host, api_key):
        self.host = host
        self.headers = {"X-Auth": api_key, "content-type": "application/json"}

    def get_target_info(self, gui_obj):
        gui_obj.clear()
        responder = requests.get(url=self.host + "scans", headers=self.headers, verify=False).json()
        if responder.get('code') == 401:
            print(responder)
        print(type(responder))
        targets_list = responder.get("scans")
        for info in targets_list:
            gui_obj.insert_before(None, [info["target"].get("address"), info.get("target_id"),
                                         info["current_session"].get("status"),
                                         info.get("scan_id"),
                                         info["current_session"]["severity_counts"].get("high"),
                                         info["current_session"]["severity_counts"].get("medium"),
                                         info["current_session"]["severity_counts"].get("low"),
                                         info["current_session"]["severity_counts"].get("info"),
                                         info["current_session"].get("start_date"),
                                         info.get("profile_name"),
                                         info["target"].get("description"),
                                         info["current_session"].get("scan_session_id")])

    def add_target_to_scan(self, address, description):
        data = {"address": address, "description": description, "criticality": "10"}
        responder = requests.post(url=self.host + "targets", data=json.dumps(data),
                                  headers=self.headers, verify=False).json()
        return responder.get("target_id")

    def config(self, target_id, data):
        responses = requests.patch(self.host + "targets/" + target_id + "/configuration",
                                   data=json.dumps(data), headers=self.headers, verify=False)
        # print(responses)

    def del_target(self, target_id):
        responses = requests.delete(self.host + "targets/" + target_id, headers=self.headers, verify=False)
        # print(responses.status_code)

    def set_speed(self, target_id, speed):
        data = {"scan_speed": speed}  # slow/moderate/fast
        self.config(target_id, data)

    def set_login(self, target_id, username, password):
        data = {"login": {"kind": "automatic",
                          "credentials": {"enabled": True, "username": username, "password": password}}}
        self.config(target_id, data)

    def set_proxy(self, target_id, ip, port):
        data = {"proxy": {"enabled": True, "address": ip, "protocol": "http", "port": port}}
        self.config(target_id, data)

    def start_scan(self, target_id, profile_id="F"):
        try:
            data = {"target_id": target_id, "profile_id": rules.get(profile_id),
                    "schedule": {"disable": False, "start_date": None, "time_sensitive": False}}
            responses = requests.post(self.host + "scans", data=json.dumps(data), headers=self.headers, verify=False)
            # print(responses)
        except Exception as e:
            print(e)

    def list_to_scan(self, text_targets_list: list, gui):
        print(f"started at {time.strftime('%X')}")
        for address in text_targets_list:
            if not address.__len__():
                return False
            if address[0:4] != "http":
                address = "http://" + address
            target_id = self.add_target_to_scan(address=address, description=gui.Edit_Description.get_text())
            if gui.Enable_Proxy.get_active():
                print("Proxy")
                self.set_proxy(target_id=target_id, ip=gui.Proxy_Port.get_text(), port=gui.Proxy_Port.get_text())
            self.set_speed(target_id=target_id, speed=gui.ComboBox_Text_Speed.get_active_text())
            self.start_scan(target_id=target_id)
        print(f"started at {time.strftime('%X')}")

    def add_scan_to_report(self, scan_id):
        data = {"template_id": "11111111-1111-1111-1111-111111111111",
                "source": {"list_type": "scans", "id_list": [scan_id]}}
        print(data)
        responder = requests.post(self.host + "reports", data=json.dumps(data), headers=self.headers,
                                  verify=False).json()
        print(responder)

    def get_report_info(self, gui_obj):
        gui_obj.clear()
        responder = requests.get(url=self.host + "reports", headers=self.headers, verify=False).json()
        print(responder)
        targets_list = responder.get("reports")
        for info in targets_list:
            gui_obj.insert_before(None, [info["source"].get("description").split(";")[0],
                                         info.get("report_id"),
                                         info.get("status"),
                                         info.get("source").get("id_list")[0],
                                         info.get("generation_date"),
                                         info.get("template_name"),
                                         info["source"].get("description").split(";")[1],
                                         str(info.get("download"))])

    def del_report_from_scan(self, report_id):
        responder = requests.delete(url=self.host + "reports/" + report_id, headers=self.headers, verify=False)


class VulnerabilitiesApi:
    def __init__(self, host, api_key):
        self.host = host
        self.headers = api_key

    def get_vulnerabilities_info(self):
        responder = requests.get(url=self.host + "vulnerabilities?q=status:open",
                                 headers=self.headers, verify=False).json()
        print(responder)

    def get_vulnerabilities_by_scan_id(self, scan_id, scan_session, widget):
        responder = requests.get(url=self.host + "scans/" + scan_id + "/results/" + scan_session + "/vulnerabilities",
                                 headers=self.headers, verify=False)
        info = json.loads(responder.text)
        for v_info in info["vulnerabilities"]:
            responder = requests.get(
                url=self.host + "scans/" + scan_id + "/results/" + scan_session + "/vulnerabilities/" + v_info.get(
                    "vuln_id"), headers=self.headers, verify=False).json()
            widget.list_store_vulnerabilities_info.insert_before(None, [
                util.list_to_tag(responder.get("tags")),
                responder.get("vt_name"),
                responder.get("affects_url"),
                str(responder.get("request").encode()),
                responder.get("affects_detail"),
                util.html_to_parser(html=str(responder.get("details").encode()),
                                    point=responder.get("affects_detail")),
                util.html_to_original(str(responder.get("details").encode()))])

    def get_vulnerabilities_by_severity(self, severity: int, widget, scan_id: str = None, scan_session: str = None):
        widget.list_store_vulnerabilities_info.clear()
        if scan_id and scan_session:
            responder = requests.get(
                url=self.host + "scans/" + scan_id + "/results/" + scan_session + "/vulnerabilities/?q=severity:" + str(
                    severity), headers=self.headers, verify=False).json()
        else:
            responder = requests.get(url=self.host + "vulnerabilities?q=severity:" + str(severity),
                                     headers=self.headers, verify=False)
            print(responder)
            info = json.loads(responder.text)
            for v_info in info["vulnerabilities"]:
                responder = requests.get(
                    url=self.host + "vulnerabilities/" + v_info.get(
                        "vuln_id"), headers=self.headers, verify=False).json()
                widget.list_store_vulnerabilities_info.insert_before(None, [
                    util.list_to_tag(responder.get("tags")),
                    responder.get("vt_name"),
                    responder.get("affects_url"),
                    str(responder.get("request").encode()),
                    responder.get("affects_detail"),
                    util.html_to_parser(html=str(responder.get("details").encode()),
                                        point=responder.get("affects_detail")),
                    util.html_to_original(str(responder.get("details").encode()))])
