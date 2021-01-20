# -*- coding: utf-8 -*-
import base64
import codecs
import contextlib
import json
import re
import socket
import threading
import time
import zlib

from RE_DATA import DEFAULT

try:
    from queue import Queue
except Exception as E:
    import Queue
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM, IPPROTO_UDP

global MAX_THREADS
global TIME_OUT
global resolv
global RUN_MODE


def add_port_banner(result_queue, host, port, proto, banner):
    """添加一个结果"""
    result_queue.put({'host': host, 'port': port, 'proto': proto, 'banner': banner})


def dqtoi(dq):
    """ip地址转数字."""
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


def itodq(intval):
    """数字转ip地址."""
    return "%u.%u.%u.%u" % ((intval >> 24) & 0x000000ff,
                            ((intval & 0x00ff0000) >> 16),
                            ((intval & 0x0000ff00) >> 8),
                            (intval & 0x000000ff))


def compile_pattern(allprobes):
    """编译re的正则表达式"""
    for probe in allprobes:
        matches = probe.get('matches')
        if isinstance(matches, list):
            for match in matches:
                try:
                    match['pattern_compiled'] = re.compile(match.get('pattern'), re.IGNORECASE | re.DOTALL)
                except Exception as err:
                    match['pattern_compiled'] = ''
        softmatches = probe.get('softmatches')
        if isinstance(softmatches, list):
            for match in softmatches:
                try:
                    match['pattern_compiled'] = re.compile(match.get('pattern'), re.IGNORECASE | re.DOTALL)
                except Exception as err:
                    match['pattern_compiled'] = ''

    return allprobes


class ServiceScan(object):
    allprobes = compile_pattern(json.loads(zlib.decompress(base64.b64decode(DEFAULT))))

    def __init__(self):
        self.sd = None

    def scan(self, host, port, protocol):

        nmap_fingerprint = {}

        in_probes, ex_probes = self.filter_probes_by_port(port, self.allprobes)

        if NMAP_ENABLE_PROBE_INCLUED and in_probes:
            probes = self.sort_probes_by_rarity(in_probes)
            nmap_fingerprint = self.scan_with_probes(host, port, protocol, probes)

        # 如果找到匹配,直接返回结果
        if nmap_fingerprint:
            return nmap_fingerprint

        if NMAP_ENABLE_PROBE_EXCLUED and ex_probes:
            nmap_fingerprint = self.scan_with_probes(host, port, protocol, ex_probes)

        return nmap_fingerprint

    def scan_with_probes(self, host, port, protocol, probes):
        """发送probes中的每个probe到端口."""
        for probe in probes:
            record = self.send_probestring_request(host, port, protocol, probe, TIME_OUT * 2)
            if bool(record.get('versioninfo')):  # 如果返回了versioninfo信息,表示已匹配,直接返回
                return record
        return {}

    def send_probestring_request(self, host, port, protocol, probe, timeout):
        """根据nmap的probestring发送请求数据包"""
        proto = probe['probe']['protocol']
        payload = probe['probe']['probestring']
        payload, _ = codecs.escape_decode(payload)

        response = ""
        # protocol must be match nmap probe protocol
        if proto.upper() == protocol.upper():
            if protocol.upper() == "TCP":
                response = self.send_tcp_request(host, port, payload, timeout)
            elif protocol.upper() == "UDP":
                response = self.send_udp_request(host, port, payload, timeout)

        nmap_service, nmap_fingerprint = self.match_probe_pattern(response, probe)
        # record = {
        #     "probe": {
        #         "probename": probe["probe"]["probename"],
        #         "probestring": probe["probe"]["probestring"]
        #     },
        #     "match": {
        #         "service": nmap_service,
        #         "versioninfo": nmap_fingerprint,
        #     }
        # }

        record = {
            "service": nmap_service,
            "versioninfo": nmap_fingerprint,
        }

        return record

    def send_tcp_request(self, host, port, payload, timeout):
        """Send tcp payloads by port number.
        """
        data = ''
        try:
            if self.sd is None:
                with contextlib.closing(socket.socket(AF_INET, SOCK_STREAM)) as client:
                    client.settimeout(TIME_OUT * 2)
                    client.connect((host, int(port)))
                    client.send(payload)
                    data = client.recv(SOCKET_READ_BUFFERSIZE)
            else:
                self.sd.send(payload)
                data = self.sd.recv(SOCKET_READ_BUFFERSIZE)

        except Exception as err:
            pass

        return data

    def send_udp_request(self, host, port, payload, timeout):
        """Send udp payloads by port number.
        """
        data = ''
        try:
            with contextlib.closing(socket.socket(AF_INET, SOCK_DGRAM)) as client:
                client.settimeout(timeout)
                client.sendto(payload, (host, port))
                while True:
                    _, addr = client.recvfrom(SOCKET_READ_BUFFERSIZE)
                    if not _:
                        break
                    data += _
        except Exception as err:
            pass
        return data

    def match_probe_pattern(self, data, probe):
        """Match tcp/udp response based on nmap probe pattern.
        """
        nmap_service, nmap_fingerprint = "", {}

        if not data:
            return nmap_service, nmap_fingerprint

        try:
            matches = probe['matches']

            for match in matches:
                # pattern = match['pattern']
                pattern_compiled = match['pattern_compiled']

                # https://github.com/nmap/nmap/blob/master/service_scan.cc#L476
                # regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)

                rfind = pattern_compiled.findall(data)

                if rfind and ("versioninfo" in match):
                    nmap_service = match['service']
                    versioninfo = match['versioninfo']

                    rfind = rfind[0]
                    rfind = [rfind] if isinstance(rfind, str) else rfind

                    # (['5.5.38-log'], <type 'list'>)
                    # ([('2.0', '5.3')], <type 'list'>)
                    # ([('2.4.7', 'www.nongnu.org')], <type 'list'>)

                    if re.search('\$P\(\d\)', versioninfo) is not None:
                        for index, value in enumerate(rfind):
                            dollar_name = "$P({})".format(index + 1)

                            versioninfo = versioninfo.replace(dollar_name, value)
                    elif re.search('\$\d', versioninfo) is not None:
                        for index, value in enumerate(rfind):
                            dollar_name = "${}".format(index + 1)

                            versioninfo = versioninfo.replace(dollar_name, value)

                    nmap_fingerprint = self.match_versioninfo(versioninfo)
                    return nmap_service, nmap_fingerprint

        except Exception as err:
            return nmap_service, nmap_fingerprint
        return nmap_service, nmap_fingerprint
        # TODO 少了softmatches

    def match_versioninfo(self, versioninfo):
        """Match Nmap versioninfo
        """
        # p/vendorproductname/
        # v/version/
        # i/info/
        # h/hostname/
        # o/operatingsystem/
        # d/devicetype/
        # cpe:/cpename/[a]

        # p/SimpleHTTPServer/ v/0.6/ i/Python 3.6.0/ cpe:/a:python:python:3.6.0/ cpe:/a:python:simplehttpserver:0.6/
        # p/Postfix smtpd/ cpe:/a:postfix:postfix/a
        # s
        # s p/TLSv1/
        # p/Postfix smtpd/ cpe:/a:postfix:postfix/a

        record = {
            "vendorproductname": [],
            "version": [],
            "info": [],
            "hostname": [],
            "operatingsystem": [],
            "cpename": []
        }

        if "p/" in versioninfo:
            regex = re.compile(r"p/([^/]*)/")
            vendorproductname = regex.findall(versioninfo)
            record["vendorproductname"] = vendorproductname

        if "v/" in versioninfo:
            regex = re.compile(r"v/([^/]*)/")
            version = regex.findall(versioninfo)
            record["version"] = version

        if "i/" in versioninfo:
            regex = re.compile(r"i/([^/]*)/")
            info = regex.findall(versioninfo)
            record["info"] = info

        if "h/" in versioninfo:
            regex = re.compile(r"h/([^/]*)/")
            hostname = regex.findall(versioninfo)
            record["hostname"] = hostname

        if "o/" in versioninfo:
            regex = re.compile(r"o/([^/]*)/")
            operatingsystem = regex.findall(versioninfo)
            record["operatingsystem"] = operatingsystem

        if "d/" in versioninfo:
            regex = re.compile(r"d/([^/]*)/")
            devicetype = regex.findall(versioninfo)
            record["devicetype"] = devicetype

        if "cpe:/" in versioninfo:
            regex = re.compile(r"cpe:/a:([^/]*)/")
            cpename = regex.findall(versioninfo)
            record["cpename"] = cpename

        return record

    def sort_probes_by_rarity(self, probes):
        """Sorts by rarity
        """
        newlist = sorted(probes, key=lambda k: k['rarity']['rarity'])
        return newlist

    def filter_probes_by_port(self, port, probes):
        """通过端口号进行过滤,返回强符合的probes和弱符合的probes
        """
        # {'match': {'pattern': '^LO_SERVER_VALIDATING_PIN\\n$',
        #            'service': 'impress-remote',
        #            'versioninfo': ' p/LibreOffice Impress remote/ '
        #                           'cpe:/a:libreoffice:libreoffice/'},
        #  'ports': {'ports': '1599'},
        #  'probe': {'probename': 'LibreOfficeImpressSCPair',
        #            'probestring': 'LO_SERVER_CLIENT_PAIR\\nNmap\\n0000\\n\\n',
        #            'protocol': 'TCP'},
        #  'rarity': {'rarity': '9'}}

        included = []
        excluded = []

        for probe in probes:
            if "ports" in probe:
                ports = probe['ports']['ports']
                if self.is_port_in_range(port, ports):
                    included.append(probe)
                else:  # exclude ports
                    excluded.append(probe)

            elif "sslports" in probe:
                sslports = probe['sslports']['sslports']
                if self.is_port_in_range(port, sslports):
                    included.append(probe)
                else:  # exclude sslports
                    excluded.append(probe)

            else:  # no [ports, sslports] settings
                excluded.append(probe)

        return included, excluded

    def is_port_in_range(self, port, nmap_port_rule):
        """Check port if is in nmap port range
        """
        bret = False

        ports = nmap_port_rule.split(',')  # split into serval string parts
        if str(port) in ports:
            bret = True
        else:
            for nmap_port in ports:
                if "-" in nmap_port:
                    s, e = nmap_port.split('-')
                    if int(port) in range(int(s), int(e)):
                        bret = True

        return bret


class ScanTheard(threading.Thread):
    def __init__(self, req_queue, result_queue):
        super(ScanTheard, self).__init__()
        self.req_queue = req_queue
        self.result_queue = result_queue
        self.serviceScan = ServiceScan()

    def run(self):
        while self.req_queue.empty() is not True:
            try:
                req_dict = self.req_queue.get(timeout=0.05)
            except Exception as E:
                continue

            host = itodq(req_dict.get('host'))
            port = req_dict.get('port')
            if isinstance(port, int):
                try:
                    self.sd = socket.socket(AF_INET, SOCK_STREAM)
                    self.sd.bind(("0.0.0.0", 0))
                    global TIME_OUT
                    global resolv
                    self.sd.settimeout(TIME_OUT)
                    self.sd.connect((host, port))
                    # self.serviceScan.sd = self.sd
                    data = self.serviceScan.scan(host, port, 'tcp')
                    self.sd.close()
                    add_port_banner(result_queue=self.result_queue, host=host, port=port, proto="TCP", banner=data)
                except Exception as E:
                    pass
            elif isinstance(port, dict):
                udp_port = port.get("UDP")
                self.sd = socket.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
                self.sd.bind(("0.0.0.0", 0))
                self.sd.settimeout(TIME_OUT)
                self.sd.connect((host, udp_port))
                banner = "no banner"
                self.sd.close()
                add_port_banner(result_queue=self.result_queue, host=host, port=port, proto="UDP", banner=banner)
            else:
                pass


def main(startip, stopip, port_list):
    start = dqtoi(startip)
    stop = dqtoi(stopip)

    try:
        req_queue = Queue.Queue()
        result_queue = Queue.Queue()
    except Exception as E:
        try:
            req_queue = Queue()
            result_queue = Queue()
        except Exception as E:

            return

    for host in range(start, stop + 1):
        for port in port_list:
            req_queue.put({'host': host, 'port': port})

    for i in range(MAX_THREADS):
        t = ScanTheard(req_queue, result_queue)
        t.start()
    while req_queue.empty() is not True:
        time.sleep(TIME_OUT)

    time.sleep(TIME_OUT * 5)

    result_list = []
    while result_queue.empty() is not True:
        tmp = result_queue.get()
        result_list.append(tmp)

    if RUN_MODE == 'single_script':
        for one in result_list:
            print(one)
    else:
        json_str = base64.b64encode(json.dumps(result_list).encode('ascii'))
        print(json_str)


# 系统函数,为了获取输入参数
def get_script_param(key):
    input_str = 'THIS IS FOR INPUT STR TO REPLACE,DO NOT CHANGE THIS STRING'
    try:
        dict_params = json.loads(base64.b64decode(input_str))
        return dict_params.get(key)
    except Exception as E:
        return {}


# main函数部分,为了确保windows的python插件能直接执行,不要放在if __name__=="__main__":函数中
RUN_MODE = 'single_script'  # 'single_script' 'viper'

SOCKET_READ_BUFFERSIZE = 1024  # SOCKET DEFAULT READ BUFFER
NMAP_ENABLE_PROBE_INCLUED = True  # Scan probes inclued target port
NMAP_ENABLE_PROBE_EXCLUED = True  # Scan probes exclued target port

if RUN_MODE == 'single_script':  # 单脚本运行模式
    TIME_OUT = 0.05
    MAX_THREADS = 1
    startip = "192.172.1.1"
    stopip = "192.172.1.14"
    port_list = [139, 445, 22]
else:  # viper插件模式
    # 获取输入参数
    if get_script_param('max_threads') is not None:
        MAX_THREADS = get_script_param('max_threads')
    if get_script_param('time_out') is not None:
        TIME_OUT = get_script_param('time_out')
    startip = get_script_param('startip')
    stopip = get_script_param('stopip')
    port_list = get_script_param('port_list')

# 开始运行
main(startip, stopip, port_list)
