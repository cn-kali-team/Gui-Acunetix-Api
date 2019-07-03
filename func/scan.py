#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import requests
import urllib3

urllib3.disable_warnings()
rules = {
    "H": '11111111-1111-1111-1111-111111111112',  # High Risk Vulnerabilities
    "W": '11111111-1111-1111-1111-111111111115',  # Weak Passwords
    "C": '11111111-1111-1111-1111-111111111117',  # Crawl Only
    "X": '11111111-1111-1111-1111-111111111116',  # Cross-site Scripting Vulnerabilities
    "S": '11111111-1111-1111-1111-111111111113',  # SQL Injection Vulnerabilities
    "F": '11111111-1111-1111-1111-111111111111'   # Full Scan
}


class ScanApi:
    def __init__(self, host, api_key):
        self.host = host
        self.headers = {"X-Auth": api_key, "content-type": "application/json"}

    def get_target_info(self, gui_obj):
        gui_obj.clear()
        responder = requests.get(url=self.host + "scans", headers=self.headers, verify=False).json()
        targets_list = responder.get("scans")
        for info in targets_list:
            gui_obj.append([info["target"].get("address"), info.get("target_id"),
                            info["current_session"].get("status"),
                            info.get("scan_id"),
                            info["current_session"]["severity_counts"].get("high"),
                            info["current_session"]["severity_counts"].get("medium"),
                            info["current_session"]["severity_counts"].get("low"),
                            info["current_session"]["severity_counts"].get("info"),
                            info["current_session"].get("start_date"),
                            info.get("profile_name"),
                            info["target"].get("description")])

    def add_target_to_scan(self, address, description):
        data = {"address": address, "description": description, "criticality": "10"}
        responder = requests.post(url=self.host + "targets", data=json.dumps(data),
                                  headers=self.headers, verify=False).json()
        return responder.get("target_id")

    def config(self, target_id, data):
        responses = requests.patch(self.host + "targets/" + target_id + "/configuration",
                                   data=json.dumps(data), headers=self.headers, verify=False)
        print(responses)

    def del_target(self, target_id):
        responses = requests.delete(self.host + "targets/" + target_id, headers=self.headers, verify=False)
        print(responses.status_code)

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
            print(responses)
        except Exception as e:
            print(e)
