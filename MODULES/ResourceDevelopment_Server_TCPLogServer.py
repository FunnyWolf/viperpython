# -*- coding: utf-8 -*-
import socketserver
import threading
import time

from Lib.ModuleAPI import *


class ListenHandler(socketserver.BaseRequestHandler):
    def handle(self):
        Notice.send_success(f"Connected with {self.client_address[0]}:{str(self.client_address[1])}\n")
        self.data = self.request.recv(1024).strip()
        Notice.send_success(f"TCP Receive Data: {self.data.decode()}")


class TCPLOGServer(threading.Thread):
    def __init__(self, host="0.0.0.0", port=-1):
        '''Create a new SOCKS4 proxy on the specified port'''

        self._host = host
        self._port = port
        self.server = None
        threading.Thread.__init__(self)

    def run(self):
        with socketserver.TCPServer((self._host, self._port),
                                    ListenHandler) as self.server:
            self.server.serve_forever()

    def stop(self):
        self.server.shutdown()


class PostModule(PostPythonModule):
    NAME_ZH = "TCPLOG服务器"
    DESC_ZH = "启动简易的TCPLOG服务器,接受显示TCP回连信息\n"

    NAME_EN = "TCPLOG Server"
    DESC_EN = "Start a simple TCPLOG server to accept TCPLOG connection back information.\n"
    MODULETYPE = TAG2TYPE.Resource_Development

    ATTCK = ["T1583.006"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/glzhutgq9pt6geec"]
    REFERENCES = [""]
    AUTHOR = ["Nova"]

    REQUIRE_SESSION = False

    OPTIONS = register_options([
        OptionInt(name='listenport',
                  tag_zh="监听端口", desc_zh="本地启动TCPLOG服务的端口",
                  tag_en="Listen Port",
                  desc_en="Port to start TCPLOG service locally",
                  ),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.session = None

    def check(self):
        """执行前的检查函数"""
        return True, None

    def run(self):
        tcplogserver_t = TCPLOGServer(port=self.param("listenport"))
        tcplogserver_t.setDaemon(True)
        tcplogserver_t.start()
        lhost = self.get_lhost()
        if lhost is None:
            lhost = "0.0.0.0"
        Notice.send_info(f'TCPLOGServer: {lhost}:{self.param("listenport")}')
        while self.exit_flag is not True:
            try:
                time.sleep(1)
            except Exception as E:
                break
        tcplogserver_t.stop()
