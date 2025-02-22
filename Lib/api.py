# -*- coding: utf-8 -*-
# @File  : api.py
# @Date  : 2021/2/25
# @Desc  :
import ipaddress
import json
import random
import re
import shlex
import socket
import string
import subprocess
import uuid
from urllib.parse import urlparse

import dns.resolver
import tldextract


def exec_system(cmd, **kwargs):
    cmd = " ".join(cmd)
    timeout = 4 * 60 * 60

    if kwargs.get('timeout'):
        timeout = kwargs['timeout']
        kwargs.pop('timeout')

    completed = subprocess.run(shlex.split(cmd), timeout=timeout, check=False, close_fds=True, **kwargs)

    return completed


def random_str(len):
    value = ''.join(random.sample(string.ascii_letters + string.digits, len))
    return value


def random_str_no_num(len):
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


def is_domain(url):
    regex = r"^([a-zA-Z]+:\/\/)?([\da-zA-Z\.-]+)\.([a-zA-Z]{2,6})([\/\w \.-]*)*\/?$"
    return True if re.match(regex, url) else False


def is_root_domain(domain):
    ext = tldextract.extract(domain)
    return ext.fqdn == domain and not ext.subdomain


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


# 定义协议及其默认端口号
DEFAULT_PORTS = {
    'http': 80,
    'https': 443,
    'ftp': 21,
    'ssh': 22,
    'telnet': 23,
    'smtp': 25,
    'redis': 6379,
    # 你可以继续添加更多协议及其默认端口号
}


def parse_url_simple(url):
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme
    # host = parsed_url.netloc
    host = parsed_url.hostname
    port = parsed_url.port or DEFAULT_PORTS.get(scheme, None)

    return scheme, host, port


def clean_record(ipdomain_port_list):
    new_list = []
    for item in ipdomain_port_list:
        ipdomain = item[0]
        port = item[1]
        new_list.append({"ipdomain": ipdomain, "port": port})

    return new_list


def get_list_common(list1, list2):
    # list1 = [{'name': 'a', 'age': 20}, {'name': 'b', 'age': 30}, {'name': 'c', 'age': 25}]
    # list2 = [{'name': 'b', 'age': 30}, {'name': 'c', 'age': 25}, {'name': 'd', 'age': 35}]

    intersect = [i for i in set(list1) & set(list2)]
    return intersect


def get_list_diff(list1, list2):
    # list1 = [{'name': 'a', 'age': 20}, {'name': 'b', 'age': 30}, {'name': 'c', 'age': 25}]
    # list2 = [{'name': 'b', 'age': 30}, {'name': 'c', 'age': 25}, {'name': 'd', 'age': 35}]
    list1 = list(list1)
    list2 = list(list2)
    for one in list2:
        if one in list1:
            list1.remove(one)
    return list1


def is_ipaddress_port_in_use(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((ip, port))
        except socket.error as e:
            if e.errno == 98:  # 地址已在使用
                return True
            else:
                raise e
        else:
            return False


def get_dns_cname(domain):
    try:
        # 创建一个DNS解析器
        resolver = dns.resolver.Resolver()

        # 查询CNAME记录
        cname = resolver.resolve(domain, 'CNAME')

        # 返回CNAME记录列表
        return [cname_record.to_text() for cname_record in cname]
    except dns.resolver.NXDOMAIN:
        print(f"Domain {domain} does not exist.")
    except dns.resolver.NoAnswer:
        print(f"No CNAME record found for {domain}.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return []


def get_dns_a(domain):
    try:
        # 创建一个DNS解析器
        resolver = dns.resolver.Resolver()

        # 查询CNAME记录
        A = resolver.resolve(domain, "A")

        # 返回CNAME记录列表
        return [a.to_text() for a in A]
    except dns.resolver.NXDOMAIN:
        print(f"Domain {domain} does not exist.")
    except dns.resolver.NoAnswer:
        print(f"No CNAME record found for {domain}.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return []
