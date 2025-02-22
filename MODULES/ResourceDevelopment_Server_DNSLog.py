# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :
import copy
import os
import re
import tempfile
import time

from dnslib import RR, QTYPE, RCODE, TXT, DNSLabel, A
from dnslib.server import DNSServer, BaseResolver

from Lib.ModuleAPI import *


class DnsLogger():
    def __init__(self, DNS_DOMAIN, MIN_SUBDOMAIN_LENGTH):
        super().__init__()
        self.DNS_DOMAIN = DNS_DOMAIN
        self.MIN_SUBDOMAIN_LENGTH = MIN_SUBDOMAIN_LENGTH

    def log_data(self, dnsobj):
        pass

    def log_error(self, handler, e):
        pass

    def log_pass(self, *args):
        pass

    def log_prefix(self, handler):
        pass

    def log_recv(self, handler, data):
        pass

    def log_reply(self, handler, reply):
        pass

    def log_request(self, handler, request):
        domain = request.q.qname.__str__().lower()
        if domain.endswith(self.DNS_DOMAIN + '.'):
            udomain = re.search(r'(\S+)\.%s\.' % self.DNS_DOMAIN,
                                domain)
            if udomain:
                try:
                    source_ip = handler.client_address[0]
                except:
                    source_ip = "127.0.0.1"

                locate_zh = IPGeo.get_ip_geo_str(source_ip, "zh-CN")
                locate_en = IPGeo.get_ip_geo_str(source_ip, "en-US")

                msg = None
                prefix = udomain.group(1)
                if len(prefix) >= self.MIN_SUBDOMAIN_LENGTH:
                    if len(prefix) == 16:
                        data = UUIDJson.list(prefix)
                        if data is not None:
                            msg = "RPCMSG"

                    if msg:
                        Notice.send_success(
                            content_cn=f"{domain[:-1]} {QTYPE[request.q.qtype]} {source_ip} {locate_zh} {msg}",
                            content_en=f"{domain[:-1]} {QTYPE[request.q.qtype]} {source_ip} {locate_en} {msg}")
                    else:
                        Notice.send_warning(
                            content_cn=f"{domain[:-1]} {QTYPE[request.q.qtype]} {source_ip} {locate_zh}",
                            content_en=f"{domain[:-1]} {QTYPE[request.q.qtype]} {source_ip} {locate_en}")

    def log_send(self, handler, data):
        pass

    def log_truncated(self, handler, reply):
        pass


class ZoneResolver(BaseResolver):
    """
        Simple fixed zone file resolver.
    """

    def __init__(self, zone, glob=False, DNS_DOMAIN=None, ADMIN_DOMAIN=None, SERVER_IP=None):
        """
            Initialise resolver from zone file.
            Stores RRs as a list of (label,type,rr) tuples
            If 'glob' is True use glob match against zone file
        """
        self.zone = [(rr.rname, QTYPE[rr.rtype], rr)
                     for rr in RR.fromZone(zone)]
        self.glob = glob
        self.eq = 'matchGlob' if glob else '__eq__'

        self.ADMIN_DOMAIN = ADMIN_DOMAIN
        self.SERVER_IP = SERVER_IP
        self.DNS_DOMAIN = DNS_DOMAIN

    def has_admin_domain(self):
        if self.ADMIN_DOMAIN and self.SERVER_IP:
            if isinstance(self.ADMIN_DOMAIN, str) and isinstance(self.SERVER_IP, str):
                return True
        return False

    def resolve(self, request, handler):
        """
            Respond to DNS request - parameters are request packet & handler.
            Method is expected to return DNS response
        """
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        if qtype == 'TXT':
            txtpath = os.path.join(tempfile.gettempdir(), str(qname).lower())
            if os.path.isfile(txtpath):
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(open(txtpath).read().strip())))
        for name, rtype, rr in self.zone:
            # Check if label & type match
            if getattr(qname, self.eq)(name) and (qtype == rtype or qtype == 'ANY' or rtype == 'CNAME'):
                # If we have a glob match fix reply label
                if self.glob:
                    a = copy.copy(rr)
                    # check admin domain
                    if self.has_admin_domain():
                        if qtype == "A" and qname == DNSLabel(f"{self.ADMIN_DOMAIN}.{self.DNS_DOMAIN}."):
                            a.rdata = A(self.SERVER_IP)
                    a.rname = qname
                    reply.add_answer(a)
                else:
                    reply.add_answer(rr)
                # Check for A/AAAA records associated with reply and
                # add in additional section
                if rtype in ['CNAME', 'NS', 'MX', 'PTR']:
                    for a_name, a_rtype, a_rr in self.zone:
                        if a_name == rr.rdata.label and a_rtype in ['A', 'AAAA']:
                            reply.add_ar(a_rr)
        if not reply.rr:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


class PostModule(PostPythonModule):
    NAME_ZH = "DNSLOG服务器"
    DESC_ZH = "启动DNSLOG服务器\n"

    NAME_EN = "DNSLOG Server"
    DESC_EN = "Start a DNSLOG server to accept dns record query information.\n"
    MODULETYPE = TAG2TYPE.Resource_Development

    ATTCK = ["T1583.006"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/nloo7z"]
    REFERENCES = [""]
    AUTHOR = ["Viper"]

    REQUIRE_SESSION = False

    OPTIONS = register_options([
        OptionStr(name='DNS_DOMAIN',
                  required=True,
                  tag_zh="DNS主域名", desc_zh="DNSLOG的主域名,例如a.com",
                  tag_en="DNS primary domain",
                  desc_en="The primary domain name of dnslog, such as a.com",
                  ),
        OptionStr(name='ADMIN_DOMAIN',
                  tag_zh="VIPER服务器域名",
                  desc_zh="用于访问Viper服务器的域名前缀,必须和`VIPER服务器IP`配合使用.(非必要参数).例如输入admin后可以通过admin.a.com访问Viper服务器",
                  tag_en="DNS primary domain",
                  desc_en="The domain name prefix used to access Viper server,must be used with 'Viper server IP' (non essential parameters).For example, after entering `admin`, you can use admin.a.com visit Viper server",
                  ),
        OptionStr(name='SERVER_IP',
                  tag_zh="VIPER服务器IP", desc_zh="VIPER服务器的IP地址,必须和`VIPER服务器域名`配合使用.",
                  tag_en="Viper server IP",
                  desc_en="The IP address of the Viper server must be used with the 'Viper server domain'",
                  ),
        OptionInt(name='MIN_SUBDOMAIN_LENGTH',
                  tag_zh="最短域名长度",
                  default=0,
                  desc_zh="DNSLOG接收的最短域名长度,例如如果设置为4,则333.a.com不会显示,4444.a.com则会显示,该配置项主要用于屏蔽互联网DNS扫描器.(建议小于16)",
                  tag_en="Minimum domain name length",
                  desc_en="The shortest domain name length received by dnslog. For example, if it is set to 4, then 333.a.com will not be displayed, 4444.a.com will be displayed. This configuration item is mainly used to shield the Internet DNS scanner",
                  ),

    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.session = None

    def check(self):
        """执行前的检查函数"""
        return True, None

    def run(self):
        zone = '''
*.{dnsdomain}.       IN      NS      {ns1domain}.
*.{dnsdomain}.       IN      NS      {ns2domain}.
*.{dnsdomain}.       IN      A       {serverip}
{dnsdomain}.       IN      A       {serverip}
'''.format(dnsdomain=self.param("DNS_DOMAIN"),
           ns1domain=f'ns1.{self.param("DNS_DOMAIN")}',
           ns2domain=f'ns2.{self.param("DNS_DOMAIN")}',
           serverip="127.0.0.1")

        resolver = ZoneResolver(zone, True,
                                DNS_DOMAIN=self.param("DNS_DOMAIN"),
                                ADMIN_DOMAIN=self.param("ADMIN_DOMAIN"),
                                SERVER_IP=self.param("SERVER_IP"))
        logger = DnsLogger(DNS_DOMAIN=self.param("DNS_DOMAIN"), MIN_SUBDOMAIN_LENGTH=self.param("MIN_SUBDOMAIN_LENGTH"))

        udp_server = DNSServer(resolver, port=53, address='0.0.0.0', logger=logger)
        udp_server.start_thread()

        while self.exit_flag is not True:
            try:
                time.sleep(1)
            except Exception as E:
                break
        udp_server.stop()
