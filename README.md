# Gui-Acunetix-Api
图形化Acunetix批量扫描工具

![1562142947188](README.assets/1562142947188.png)

## 开发环境

- Python3.7

---

- PyGObject
- requests

```bash
pip3 install -r requirements.txt
```

## 使用说明

0. 第一步，先更改你的当前目录下的config.ini文件，修改从Web端获取你的api密钥，和扫描器的地址，支持多过扫描器，可以在下拉列表框里全局选择扫描器。

1. 单个目标扫描：填写目标地址到标签：目标，后面的文本框，点击单个扫描
2. 批量扫描：按照每行一个目标地址，填写到多行文本框，也可以将拖放文本到标签：“把文件拖放到这里”，自动导入目标地址。
3. 可选：扫描速度，设置代理
4. 其实还有很多功能没有写完，只在本机测试成功过，有bug请在issues提交，并说明运行环境。

## TODO

- [ ] 先把Windows版本的功能全部重写

## License

- GNU LESSER GENERAL PUBLIC LICENSE Version 3, 29 June 2007