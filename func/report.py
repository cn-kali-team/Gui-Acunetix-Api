sql_injection_report_template = """
## 任务ID：{task_id}
- 验证节点服务器：{api_url}
- 存在漏洞的URL：{url}; 提交的Data参数：{data}
- 数据库类型：{dbms}； 数据库版本：{dbms_version}
- 注入类型：
```
{injection_type}
```
- 注入Payload：
```
{payload}
```
---
"""


def save_to_md(tree_view, file_path):
    print(file_path)
    model = tree_view.get_model()
    with open(file=file_path,mode="w") as md:

        for row in model:
            api_url, task_id, status, url, data, dbms, dbms_version, injection_type, payload = row
            report_md = sql_injection_report_template.format(api_url=api_url, task_id=task_id, url=url, data=data,
                                                             dbms=dbms, dbms_version=dbms_version,
                                                             injection_type=injection_type, payload=payload)
            md.write(report_md)
