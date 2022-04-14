# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

import socketserver

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import threading

import time

from Lib.ModuleAPI import *


class Serializer():
    """
    Stack-based Serialization utility.
    """

    __payload: bytes
    __size_stack: bytes

    def __init__(self):
        self.__payload = b""
        self.__size_stack = []

    def push(self, data: bytes) -> "Serializer":
        self.__last = data
        self.__payload = data + self.__payload
        return self

    def pop_size(self) -> "Serializer":
        return self.push(bytes([len(self.__payload) - self.__size_stack.pop()]))

    def push_size(self, count=1) -> "Serializer":
        for _ in range(count):
            self.__size_stack.append(len(self.__payload))

        return self

    def build(self) -> bytes:
        return self.__payload

    def __repr__(self) -> str:
        return f"Serializer{self.__payload}"


class LDAPResponse():
    """
    Builder for LDAP query response.
    """

    __query_name: str
    __attributes: dict

    def __init__(self, query_name: str, attributes: dict):
        self.__query_name = query_name
        self.__attributes = attributes

    def serialize(self) -> bytes:
        s = Serializer()
        s.push_size(2)
        for k, v in reversed(self.__attributes.items()):
            s.push_size(3).push(v.encode()).pop_size().push(b"\x04").pop_size().push(b"1")
            s.push_size().push(k.encode()).pop_size().push(b"\x04").pop_size().push(b"0")

        s.push(b"0\x81\x82")
        s.push_size().push(self.__query_name.encode()).pop_size().push(b"\x04").pop_size()
        s.push(b"\x02\x01\x02d\x81").pop_size().push(b"0\x81")

        SUCCESS_RESPONSE = b"0\x0c\x02\x01\x02e\x07\n\x01\x00\x04\x00\x04\x00"
        return s.build() + SUCCESS_RESPONSE


class LDAPHandler(socketserver.BaseRequestHandler):
    """
    Malicious query handler.
    """

    def __init__(self, uuid_list, unrepeat):
        self.uuid_list = uuid_list
        self.unrepeat = unrepeat

    def __call__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def handle(self):
        handshake = self.request.recv(8096)
        self.request.sendall(b"0\x0c\x02\x01\x01a\x07\n\x01\x00\x04\x00\x04\x00")
        time.sleep(0.5)
        query = self.request.recv(8096)
        if len(query) < 10:
            return
        query_name = query[9:9 + query[8:][0]].decode()
        if self.unrepeat:
            if query_name in self.uuid_list:
                self.request.close()
                return
            else:
                self.uuid_list.append(query_name)

        Notice.send_success(f"LDAP IP: {self.request.getpeername()[0]}  UUID: {query_name}")
        response = LDAPResponse(query_name, {
            "objectClass": "javaNamingReference",
            "javaFactory": "hello"
        })
        self.request.sendall(response.serialize())

        time.sleep(0.5)

        self.request.close()


class LDAPServer(threading.Thread):
    '''LDAPServer'''

    def __init__(self, host="0.0.0.0", port=-1, unrepeat=True):
        '''Create a new SOCKS4 proxy on the specified port'''

        self._host = host
        self._port = port
        self.server = None
        self.uuid_list = []
        self.unrepeat = unrepeat
        threading.Thread.__init__(self)

    def run(self):
        with socketserver.TCPServer((self._host, self._port),
                                    LDAPHandler(uuid_list=self.uuid_list, unrepeat=self.unrepeat)) as self.server:
            self.server.serve_forever()

    def stop(self):
        self.server.shutdown()


class PostModule(PostPythonModule):
    NAME_ZH = "LDAP服务器"
    DESC_ZH = "启动简易的LDAP服务器,用于接受LDAP回连信息\n"

    NAME_EN = "LDAP Server"
    DESC_EN = "Start a simple LDAP server to accept LDAP connection back information.\n"
    MODULETYPE = TAG2TYPE.Resource_Development

    ATTCK = ["T1583.006"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/pgtssa"]
    REFERENCES = [""]
    AUTHOR = ["Viper"]

    REQUIRE_SESSION = False

    OPTIONS = register_options([
        OptionInt(name='listenport',
                  tag_zh="监听端口", desc_zh="本地启动LDAP服务的端口",
                  tag_en="Listen Port",
                  desc_en="Port to start LDAP service locally",
                  ),
        OptionBool(name='unrepeat',
                   tag_zh="去重", desc_zh="不显示重复UUID",
                   tag_en="Unrepeat",
                   desc_en="Do not display duplicate UUIDs",
                   default=True,
                   ),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.session = None

    def check(self):
        """执行前的检查函数"""
        return True, None

    def run(self):
        ldapserver_t = LDAPServer(port=self.param("listenport"), unrepeat=self.param("unrepeat"))
        ldapserver_t.setDaemon(True)
        ldapserver_t.start()
        lhost = self.get_lhost()
        if lhost is None:
            lhost = "0.0.0.0"
        Notice.send_info(f'LDAPServer: {lhost}:{self.param("listenport")}')
        while self.exit_flag is not True:
            try:
                time.sleep(1)
            except Exception as E:
                break
        ldapserver_t.stop()
