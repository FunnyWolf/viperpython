# -*- coding: utf-8 -*-
# @File  : api.py
# @Date  : 2021/2/25
# @Desc  :
import ipaddress
import json
import random
import re
import string
import uuid
from urllib.parse import urlparse

from Lib.log import logger


def random_str(len):
    value = ''.join(random.sample(string.ascii_letters + string.digits, len))
    return value


def random_int(num):
    """生成随机字符串"""
    return random.randint(1, num)


def is_json(data):
    try:
        json.loads(data)
        return True
    except Exception as E:
        return False


def is_ipaddress(ip_str):
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return True
    except Exception as E:
        return False


def is_website(url):
    regex = r"^([a-zA-Z]+:\/\/)?([\da-zA-Z\.-]+)\.([a-zA-Z]{2,6})([\/\w \.-]*)*\/?$"
    return True if re.match(regex, url) else False


def get_one_uuid_str():
    uuid_str = str(uuid.uuid1()).replace('-', "")[0:16]
    return uuid_str


def data_return(code=500, data=None,
                msg_zh="服务器发生错误，请检查服务器",
                msg_en="An error occurred on the server, please check the server."):
    return {'code': code, 'data': data, 'msg_zh': msg_zh, "msg_en": msg_en}


class UnicodeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode(encoding='utf-8', errors="ignore").encode(encoding='utf-8', errors="ignore")
        elif isinstance(obj, str):
            return obj.encode(encoding='utf-8', errors="ignore").decode(encoding='utf-8', errors="ignore")
        return json.JSONEncoder.default(self, obj)


class UnicodeDecoder(json.JSONDecoder):
    def decode(self, s):
        s = s.encode(encoding='utf-8', errors="ignore").decode(encoding='utf-8', errors="ignore")
        return super().decode(s)


def u_json_dumps(data):
    return json.dumps(data, cls=UnicodeEncoder)


def u_json_loads(data):
    return json.loads(data, cls=UnicodeDecoder)


def dqtoi(dq):
    """将字符串ip地址转换为int数字."""
    octets = dq.split(".")
    if len(octets) != 4:
        raise ValueError
    for octet in octets:
        if int(octet) > 255:
            raise ValueError
    return (int(octets[0]) << 24) + \
        (int(octets[1]) << 16) + \
        (int(octets[2]) << 8) + \
        (int(octets[3]))


def str_to_ips(ipstr):
    """字符串转ip地址列表"""
    iplist = []
    lines = ipstr.split(",")
    for raw in lines:
        if '/' in raw:
            addr, mask = raw.split('/')
            mask = int(mask)

            bin_addr = ''.join([(8 - len(bin(int(i))[2:])) * '0' + bin(int(i))[2:] for i in addr.split('.')])
            start = bin_addr[:mask] + (32 - mask) * '0'
            end = bin_addr[:mask] + (32 - mask) * '1'
            bin_addrs = [(32 - len(bin(int(i))[2:])) * '0' + bin(i)[2:] for i in
                         range(int(start, 2), int(end, 2) + 1)]

            dec_addrs = ['.'.join([str(int(bin_addr[8 * i:8 * (i + 1)], 2)) for i in range(0, 4)]) for bin_addr in
                         bin_addrs]

            iplist.extend(dec_addrs)

        elif '-' in raw:
            addr, end = raw.split('-')
            end = int(end)
            start = int(addr.split('.')[3])
            prefix = '.'.join(addr.split('.')[:-1])
            addrs = [prefix + '.' + str(i) for i in range(start, end + 1)]
            iplist.extend(addrs)
            return addrs
        else:
            iplist.extend([raw])
    return iplist


def urlParser(target):
    ssl = False
    o = urlparse(target)
    if o[0] not in ['http', 'https', '']:
        logger.error('scheme %s not supported' % o[0])
        return
    if o[0] == 'https':
        ssl = True
    if len(o[2]) > 0:
        path = o[2]
    else:
        path = '/'
    tmp = o[1].split(':')
    if len(tmp) > 1:
        port = tmp[1]
    else:
        port = None
    hostname = tmp[0]
    query = o[4]
    return (hostname, port, path, query, ssl)
