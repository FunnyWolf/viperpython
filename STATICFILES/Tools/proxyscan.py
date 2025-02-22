# -*- coding: utf-8 -*-
# @File  : log4j_scan.py
# @Date  : 2021/12/16
# @Desc  :
"""Modify HTTP query parameters."""
import json
import random
import string

import redis
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


VIPER_PROXY_HTTP_SCAN_DATA = "VIPER_PROXY_HTTP_SCAN_DATA"


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
            data = json.dumps(data)
            result = self.rcon.publish(VIPER_PROXY_HTTP_SCAN_DATA, data)
        except Exception as E:
            ctx.log.error(E)
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


class ProxyScanAddon(object):
    def __init__(self):
        self.rcon = RedisClient()

    def decode(self, data):
        if data is None:
            return data
        elif isinstance(data, str):
            return data
        else:
            try:
                return data.decode('utf-8', 'ignore')
            except Exception as E:
                ctx.log.error(E)
                return None

    def request(self, flow: http.HTTPFlow) -> None:
        pass

    def response(self, flow: http.HTTPFlow):
        if flow.request.stream:
            return
        request = {
            "content": self.decode(flow.request.content),
            "cookies": dict(flow.request.cookies),
            "headers": dict(flow.request.headers),
            "host": flow.request.host,
            "host_header": flow.request.host_header,
            "http_version": flow.request.http_version,
            "method": flow.request.method,
            "multipart_form": dict(flow.request.multipart_form),
            "path": flow.request.path,
            "path_components": flow.request.path_components,
            "port": flow.request.port,
            "pretty_host": flow.request.pretty_host,
            "pretty_url": flow.request.pretty_url,
            "query": dict(flow.request.query),
            "raw_content": self.decode(flow.request.raw_content),
            "scheme": flow.request.scheme,
            "stream": flow.request.stream,
            "text": flow.request.text,
            "timestamp_end": flow.request.timestamp_end,
            "timestamp_start": flow.request.timestamp_start,
            "url": flow.request.url,
            "urlencoded_form": dict(flow.request.urlencoded_form),
        }
        response = {
            "content": self.decode(flow.response.content),
            "cookies": dict(flow.response.cookies),
            "headers": dict(flow.response.headers),
            "http_version": flow.response.http_version,
            "raw_content": self.decode(flow.request.raw_content),
            "status_code": flow.response.status_code,
            "text": flow.response.text,
            "timestamp_end": flow.response.timestamp_end,
            "timestamp_start": flow.response.timestamp_start,
        }
        self.rcon.publish_data({"request": request, "response": response})


## main
addons = [
    ProxyScanAddon()
]
