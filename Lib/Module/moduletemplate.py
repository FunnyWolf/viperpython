# -*- coding: utf-8 -*-
# @File  : moduletemplate.py
# @Date  : 2019/1/11
# @Desc  :

import base64
import ctypes
import inspect
import json
import os
import random
import re
import string
import threading
import time
import zipfile
from ipaddress import summarize_address_range, IPv4Network, IPv4Address

from jinja2 import Environment, FileSystemLoader

from Core.Handle.host import Host
from Lib.Module.configs import BROKER, TAG2TYPE, FILE_OPTION, HANDLER_OPTION, CACHE_HANDLER_OPTION, CREDENTIAL_OPTION
from Lib.Module.configs import MODULE_DATA_DIR
from Lib.configs import MSFLOOT
from Lib.file import File
from Lib.log import logger
from Lib.xcache import Xcache
from Msgrpc.Handle.filemsf import FileMsf
from Msgrpc.Handle.handler import Handler
from Msgrpc.Handle.payload import Payload
from PostLateral.Handle.credential import Credential
from PostLateral.Handle.portservice import PortService
from PostLateral.Handle.vulnerability import Vulnerability


class _CommonModule(object):
    MODULE_BROKER = BROKER.empty

    NAME_ZH = "基础模块"  # 模块名
    DESC_ZH = "基础描述"  # 描述
    NAME_EN = "Base module"  # 模块名
    DESC_EN = "Base desc"  # 描述
    WARN_ZH = None  # 警告信息
    WARN_EN = None  # 警告信息

    AUTHOR = ["NoOne"]  # 作者
    REFERENCES = []  # 参考链接
    README = []  # 官方使用文档

    MODULETYPE = TAG2TYPE.example  # 模块类型
    OPTIONS = []  # 注册参数

    # post类模块描述
    REQUIRE_SESSION = False  # 模块是否需要Session
    PLATFORM = ["Windows", "Linux"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", "Root"]  # 所需权限
    ATTCK = [""]  # ATTCK向量

    # bot类模块描述
    SEARCH = ''

    def __init__(self, custom_param):

        super().__init__()  # 父类无需入参
        self._custom_param = custom_param  # 前端传入的参数信息
        self._ipaddress = None  # 补齐默认参数,为了Serializer
        self._sessionid = None  # 补齐默认参数,为了Serializer
        self._ip = None  # 补齐默认参数,为了Serializer
        self._port = None  # 补齐默认参数,为了Serializer
        self._protocol = None  # 补齐默认参数,为了Serializer
        self._module_uuid = None  # 为了存储uuid设置的字段
        self.opts = {}  # 用于存储msf模块的options

    # 公用函数

    def check(self):
        """执行前的检查函数,子类需要重新实现"""
        return True, None

    @property
    def loadpath(self):
        """获取模块加载路径"""
        return self.__module__

    @property
    def host_ipaddress(self):
        """运行模块的主机ip地址"""
        return None

    def set_msf_option(self, key, value):
        """设置msf模块参数"""
        self.opts[key] = value  # msf模块参数

    # 模块参数相关函数
    # 模块参数相关函数

    def param(self, name):
        """获取输入参数的接口"""
        if name in [HANDLER_OPTION.get('name'), CREDENTIAL_OPTION.get('name'), FILE_OPTION.get('name')]:
            if self._custom_param.get(name) is None:
                return None
            try:
                tmp_param = json.loads(self._custom_param.get(name))
                return tmp_param
            except Exception as E:
                logger.warning(E)
                logger.warning(self._custom_param)
                return None

        else:
            return self._custom_param.get(name)

    # 文件操作相关函数
    # 文件操作相关函数

    def _get_option_fileinfo(self):
        """获取选项中的文件详细信息"""
        fileinfo = self.param(FILE_OPTION.get('name'))
        return fileinfo

    def get_fileoption_filepath(self):
        """获取选项中的文件绝对路径"""
        file = self.param(FILE_OPTION.get('name'))
        if file is None:
            return None

        filename = file.get("name")
        filepath = File.safe_os_path_join(MSFLOOT, filename)
        return filepath

    def get_fileoption_filename(self):
        """获取选项中的文件名"""
        fileinfo = self._get_option_fileinfo()
        if fileinfo is None:
            return None
        else:
            filename = self.param(FILE_OPTION.get('name')).get("name")
            return filename

    @property
    def target_str(self):
        """返回模块实例的标识"""
        if self._sessionid is not None and self._sessionid != -1:
            return f"SID: {self._sessionid}"
        elif self._ipaddress is not None:
            return f"IP: {self.host_ipaddress}"
        elif self._ip is not None:
            return f"IP: {self.host_ipaddress}"
        else:
            return ""

    @property
    def module_data_dir(self):
        """模块对应的Data目录路径"""
        return os.path.join(MODULE_DATA_DIR, self.loadpath.split(".")[-1])

    def generate_context_by_template(self, filename, **kwargs):
        """根据模板获取内容"""
        env = Environment(loader=FileSystemLoader(self.module_data_dir))
        tpl = env.get_template(filename)
        context = tpl.render(**kwargs)
        return context

    def write_zip_vs_project(self, filename, source_code, source_code_filename="main.cpp",
                             exe_file=None,
                             exe_data=None):

        projectfile = os.path.join(File.loot_dir(), filename)
        new_zip = zipfile.ZipFile(projectfile, 'w')
        sourcepath = os.path.join(self.module_data_dir, "source")
        for file in os.listdir(sourcepath):
            src_file = os.path.join(sourcepath, file)
            new_zip.write(src_file, arcname=file, compress_type=zipfile.ZIP_DEFLATED)
        new_zip.writestr(zinfo_or_arcname=source_code_filename, data=source_code, compress_type=zipfile.ZIP_DEFLATED)
        if exe_file is not None:
            new_zip.writestr(zinfo_or_arcname=exe_file, data=exe_data,
                             compress_type=zipfile.ZIP_DEFLATED)

        new_zip.close()
        return True

    def write_zip_loader_shellcode_project(self, filename, loader_filename=None, loader_data=None, shellcode_file=None,
                                           shellcode_data=None):

        projectfile = os.path.join(File.loot_dir(), filename)
        new_zip = zipfile.ZipFile(projectfile, 'w')

        readme = os.path.join(self.module_data_dir, "readme.md")
        new_zip.write(readme, arcname="readme.md", compress_type=zipfile.ZIP_DEFLATED)

        new_zip.writestr(zinfo_or_arcname=loader_filename, data=loader_data, compress_type=zipfile.ZIP_DEFLATED)
        new_zip.writestr(zinfo_or_arcname=shellcode_file, data=shellcode_data, compress_type=zipfile.ZIP_DEFLATED)

        new_zip.close()
        return True

    # 新增数据相关函数
    # 新增数据相关函数

    def add_portservice(self, ipaddress, port, banner=None, service=""):
        """增加一个端口/服务信息"""
        if banner is None:
            banner = {}

        if isinstance(banner, dict) is not True:
            logger.warning(f'数据类型检查错误,数据 {banner}')
            banner = {}
        result = PortService.add_or_update(ipaddress=ipaddress, port=port, banner=banner, service=service)
        return result

    def add_credential(self, username='', password='', password_type='', tag=None, desc=''):
        """增加一个凭证信息"""
        if tag is None:
            tag = {}
        if isinstance(tag, dict) is not True:
            logger.warning(f'数据类型检查错误,数据 {tag}')
            tag = {}
        if password == '' or password.find('n.a.(') > 0 or len(password) > 100:
            return False
        result = Credential.add_or_update(username, password, password_type, tag, f"{self.NAME_ZH}|{self.NAME_EN}",
                                          self.host_ipaddress,
                                          desc)
        return result

    def add_vulnerability(self, ipaddress=None, extra_data=None, desc=''):
        """增加一个漏洞信息"""
        if extra_data is None:
            extra_data = {}
        if isinstance(extra_data, dict) is not True:
            logger.warning(f'数据类型检查错误,数据 {extra_data}')
            extra_data = {}

        result = Vulnerability.add_or_update(ipaddress, self.loadpath, extra_data, desc)
        return result

    def add_host(self, ipaddress, source, linktype, data):
        """新增主机
        ipaddress:新增主机ip地址
        source:数据来源,ip地址格式
        linktype: 如何连接到网络拓扑中, "scan"标识通过网络扫描新增主机,source必须填写正确ip地址
        data:补充信息 {"method": "arp"}
        """
        result = Host.create_host(ipaddress, source, linktype, data)
        return result

    def get_credential_config(self):
        """"""
        credential_record = self.param(CREDENTIAL_OPTION.get('name'))
        return credential_record

    # 模块输出相关函数
    # 模块输出相关函数
    def _log(self, log_type, data_zh, data_en=None):
        if not isinstance(data_zh, str):
            data_zh = str(data_zh)
        if data_en is not None and not isinstance(data_en, str):
            data_en = str(data_en)
        result_format = {"type": log_type, "data_zh": data_zh, "data_en": data_en}
        Xcache.add_module_result(self.host_ipaddress, self.loadpath, result_format)

    def log_table(self, data_zh, data_en):
        if data_zh is None or len(data_zh) == 0:
            return
        if data_en is None or len(data_en) == 0:
            return
        columns_zh = []
        for key in data_zh[0]:
            columns_zh.append({"title": key, "dataIndex": key})

        columns_en = []
        for key in data_en[0]:
            columns_en.append({"title": key, "dataIndex": key})

        result_format = {"type": "table",
                         "data_zh": data_zh, "data_en": data_en,
                         "columns_zh": columns_zh, "columns_en": columns_en}

        Xcache.add_module_result(self.host_ipaddress, self.loadpath, result_format)

    def log_raw(self, data):
        if data is None:
            return
        self._log("raw", data, data)

    def log_info(self, data_zh, data_en=None):
        self._log("info", data_zh, data_en)

    def log_success(self, data_zh, data_en=None):
        self._log("good", data_zh, data_en)

    def log_good(self, data_zh, data_en=None):
        self._log("good", data_zh, data_en)

    def log_warn(self, data_zh, data_en=None):
        self._log("warning", data_zh, data_en)

    def log_warning(self, data_zh, data_en=None):
        self._log("warning", data_zh, data_en)

    def log_error(self, data_zh, data_en=None):
        self._log("error", data_zh, data_en)

    def log_except(self, data_zh, data_en=None):
        self._log("except", data_zh, data_en)

    def log_store(self, result_format):
        """清空已有结果并存储当前输出"""
        result_format = result_format.strip()
        Xcache.set_module_result(self.host_ipaddress, self.loadpath, result_format)

    def clean_log(self):
        flag = Xcache.del_module_result_by_ipaddress_and_loadpath(self.host_ipaddress, self.loadpath)
        return flag

    def store_result_in_history(self):
        """存储模块运行结果到历史记录"""
        if self.MODULETYPE in [TAG2TYPE.internal]:  # 内部模块不存储
            return True

        module_result = Xcache.get_module_result(ipaddress=self.host_ipaddress,
                                                 loadpath=self.__module__)

        flag = Xcache.add_module_result_history(
            ipaddress=self.host_ipaddress,
            sessionid=self._sessionid,
            loadpath=self.__module__,
            opts=self.get_readable_opts(),
            update_time=module_result.get("update_time"),
            result=module_result.get("result"))
        return flag

    def get_readable_opts(self):
        opts = {}
        for key in self._custom_param:
            for option in self.OPTIONS:
                if option.get("name") == key:
                    if self._custom_param.get(key) is None:
                        continue
                    opts[option.get("name")] = {"tag_zh": option.get("tag_zh"),
                                                "tag_en": option.get("tag_en"),
                                                "data": self._custom_param.get(key)}

                    # 处理凭证,监听,文件等参数
                    try:
                        if key == HANDLER_OPTION.get("name"):
                            handler_dict = json.loads(self._custom_param.get(key))
                            # 清理无效的参数
                            new_params = {
                                "PAYLOAD": handler_dict.get("PAYLOAD"),
                                "LPORT": handler_dict.get("LPORT")
                            }
                            if handler_dict.get("LHOST") is not None:
                                new_params["LHOST"] = handler_dict.get("LHOST")
                            if handler_dict.get("RHOST") is not None:
                                new_params["RHOST"] = handler_dict.get("RHOST")

                            opts[option.get("name")] = {"tag_zh": option.get("tag_zh"),
                                                        "tag_en": option.get("tag_en"),
                                                        "data": json.dumps(new_params)}

                        elif key == FILE_OPTION.get("name"):
                            file_dict = json.loads(self._custom_param.get(key))
                            opts[option.get("name")] = {"tag_zh": option.get("tag_zh"),
                                                        "tag_en": option.get("tag_en"),
                                                        "data": file_dict.get("name")}

                        elif key == CREDENTIAL_OPTION.get("name"):
                            credential_dict = json.loads(self._custom_param.get(key))
                            opts[option.get("name")] = {"tag_zh": option.get("tag_zh"),
                                                        "tag_en": option.get("tag_en"),
                                                        "data": json.dumps({
                                                            "username": credential_dict.get("username"),
                                                            "password": credential_dict.get("password"),
                                                            "password_type": credential_dict.get("password_type"),
                                                        })}

                    except Exception as E:
                        logger.exception(E)

                    # 处理text类型参数
                    try:
                        if option.get("type") == "text":
                            opts[option.get("name")] = {"tag_zh": option.get("tag_zh"),
                                                        "tag_en": option.get("tag_en"),
                                                        "data": self._custom_param.get(key)[0:30]}
                        if option.get("type") == "bool":
                            if self._custom_param.get(key):
                                data = "True"
                            elif self._custom_param.get(key) is None:
                                data = "None"
                            else:
                                data = "False"

                            opts[option.get("name")] = {"tag_zh": option.get("tag_zh"),
                                                        "tag_en": option.get("tag_en"),
                                                        "data": data}
                    except Exception as E:
                        logger.exception(E)

        return opts

    # 监听相关函数
    def set_payload_by_handler(self):
        """通过handler参数设置msf模块的payload"""
        handler_config = self.param(HANDLER_OPTION.get('name'))
        if handler_config is None:
            return False
        z = self.opts.copy()
        z.update(handler_config)
        if "bind" in z.get("PAYLOAD"):
            z['disablepayloadhandler'] = False
        else:
            z['disablepayloadhandler'] = True
        self.opts = z
        return True

    def cache_handler(self):
        """根据模块监听配置生成虚拟监听"""
        if self.param(CACHE_HANDLER_OPTION.get("name")):
            handler_config = self.param(HANDLER_OPTION.get('name'))
            if handler_config is None:
                return False

            handler_config["HandlerName"] = f"{self.NAME_EN} IP: {self.host_ipaddress}"
            Handler.create_virtual_handler(handler_config)
            self.log_info("监听配置已缓存", "Hander configuration is cached")
            return True
        else:
            return False

    def create_handler(self, opts):
        """新增监听"""
        connext = Handler.create(opts)
        code = connext.get("code")
        if code == 201:
            return True, connext
        elif code in [301]:
            return False, connext
        else:
            return False, connext

    def get_handler_payload(self):
        """通过handler参数获取msf模块的payload"""
        handler_config = self.param(HANDLER_OPTION.get('name'))
        if handler_config is None:
            return None
        else:
            payload = handler_config.get("PAYLOAD")
            return payload

    def get_handler_config(self):
        """获取handler详细配置信息"""
        handler_config = self.param(HANDLER_OPTION.get('name'))
        return handler_config

    def generate_payload(self, format):
        """通过监听配置生成指定格式的payload"""
        handler_config = self.param(HANDLER_OPTION.get('name'))
        if handler_config is None:
            return None
        handler_config["Format"] = format
        payload_data = Payload.generate_payload(mname=handler_config.get("PAYLOAD"), opts=handler_config)
        return payload_data

    def generate_bypass_exe_data(self, template):
        """通过监听配置生成exe,返回exe内容"""
        handler_config = self.param(HANDLER_OPTION.get('name'))
        if handler_config is None:
            return None
        bytedata = Payload.generate_bypass_exe(mname=handler_config.get("PAYLOAD"), opts=handler_config,
                                               template=template)

        return bytedata

    def generate_bypass_exe_file(self, template):
        """通过监听配置生成exe,返回exe文件路径"""
        handler_config = self.param(HANDLER_OPTION.get('name'))
        if handler_config is None:
            return None
        bytedata = Payload.generate_bypass_exe(mname=handler_config.get("PAYLOAD"), opts=handler_config,
                                               template=template)
        filename = f"tmp_{int(time.time())}.exe"
        filepath = FileMsf.write_msf_file(filename, bytedata)
        return filepath

    def get_lhost(self):
        cache_data = Xcache.get_lhost_config()
        return cache_data.get("lhost")

    # 功能函数
    @staticmethod
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

    def str_to_ips(self, ipstr):
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

    @staticmethod
    def timestamp_to_str(timestamp):
        """将时间戳转换为字符串."""
        time_array = time.localtime(timestamp)
        other_style_time = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
        return other_style_time

    @staticmethod
    def random_str(num):
        """生成随机字符串"""
        salt = ''.join(random.sample(string.ascii_letters, num))
        return salt


class ProxyHttpScanModule(_CommonModule):
    MODULE_BROKER = BROKER.proxy_http_scan_module
    MODULETYPE = TAG2TYPE.Proxy_Http_Scan

    def __init__(self, custom_param):
        super().__init__(custom_param)  # 父类无需入参

        # 设置内部参数
        self._custom_param = custom_param  # 前端传入的参数信息

    def callback(self, request, response, data=None):
        """后台运行模块回调函数"""
        logger.warning(self._custom_param)
        logger.warning(request)
        logger.warning(response)
        logger.warning(data)


class _BotCommonModule(_CommonModule):
    """bot模块基础模板"""
    SEARCH = ''

    def __init__(self, ip, port, protocol, custom_param):
        super().__init__(custom_param)  # 父类无需入参

        # 设置内部参数
        self._ip = ip  # 前端传入的ip地址
        self._port = port  # 前端传入的端口信息
        self._protocol = protocol  # 前端传入的协议类型
        self._custom_param = custom_param  # 前端传入的参数信息

    @property
    def host_ipaddress(self):
        """重载host_ipaddress函数"""
        return self._ip


class BotPythonModule(_BotCommonModule):
    """bot msf模块(全网扫描)基础模板"""
    MODULE_BROKER = BROKER.bot_python_module

    def __init__(self, ip, port, protocol, custom_param):
        super().__init__(ip, port, protocol, custom_param)  # 父类无需入参

    def run(self):
        """后台运行模块回调函数"""
        self.log_error("模块中未实现run函数", "The run function is not implemented in the module")


class BotMSFModule(_BotCommonModule):
    """bot msf模块(全网扫描)基础模板"""
    MODULE_BROKER = BROKER.bot_msf_module

    def __init__(self, ip, port, protocol, custom_param):
        super().__init__(ip, port, protocol, custom_param)  # 父类无需入参

        # 设置模块参数
        self.type = None  # msf模块类型
        self.mname = None  # msf模块路径
        self.opts = {}  # 设置MSF模块的必填参数
        self.timeout = 60  # 模块运行的超时时间(秒)

    def callback(self, module_output):
        """后台运行模块回调函数"""
        logger.warning(self.type)
        logger.warning(self.mname)
        logger.warning(self.opts)
        logger.warning(module_output)


class _PostCommonModule(_CommonModule):
    """post类模块基础模板"""
    MODULE_BROKER = BROKER.post_msf_job

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(custom_param)  # 父类无需入参
        # 设置内部参数
        self._ipaddress = ipaddress  # 前端传入的ipaddress信息
        self._sessionid = sessionid  # 前端传入的sessionid

    @property
    def host_ipaddress(self):
        """重载host_ipaddress参数"""
        return self._ipaddress

    def param_address_range(self, name="address_range"):
        raw_input = self._custom_param.get(name)

        try:
            raw_lines = raw_input.split(",")
        except Exception as E:
            logger.exception(E)
            return []
        ipaddress_list = []
        for line in raw_lines:
            if '-' in line:
                try:
                    startip = line.split("-")[0]
                    endip = line.split("-")[1]
                    ipnetwork_list = summarize_address_range(IPv4Address(startip), IPv4Address(endip))
                    for ipnetwork in ipnetwork_list:
                        for ip in ipnetwork:
                            if ip.compressed not in ipaddress_list:
                                ipaddress_list.append(ip.compressed)
                except Exception as E:
                    logger.exception(E)
            elif line == "":
                continue
            else:
                try:
                    ipnetwork = IPv4Network(line)
                    for ip in ipnetwork:
                        if ip.compressed not in ipaddress_list:
                            ipaddress_list.append(ip.compressed)
                except Exception as E:
                    logger.exception(E)

        return ipaddress_list


class _PostMSFModuleCommon(_PostCommonModule):
    """msf模块后台运行基础模板"""
    MODULE_BROKER = BROKER.post_msf_job

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)  # 父类无需入参

        # 设置MSF模块参数
        self.type = None  # msf模块类型
        self.mname = None  # msf模块路径
        self.opts = {'SESSION': self._sessionid}  # 设置MSF模块的必填参数

    def callback(self, status, message, data):
        """后台运行模块回调函数"""
        logger.warning(self.type)
        logger.warning(self.mname)
        logger.warning(self.opts)

    @staticmethod
    def deal_powershell_json_result(result):
        result_without_error = re.sub('ERROR:.+\s', '', result)
        result_without_empty = result_without_error.replace('\r', '').replace('\n', '').replace('\t', '')
        try:
            result_json = json.loads(result_without_empty)
            return result_json
        except Exception as E:
            logger.warning(E)
            logger.warning("解析powershell结果失败")
            logger.warning(result_without_empty)
            return None


def _async_raise(tid, exctype):
    """Raises an exception in the threads with id tid"""
    if not inspect.isclass(exctype):
        raise TypeError("Only types can be raised (not instances)")
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid),
                                                     ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # "if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"
        ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


class ThreadWithExc(threading.Thread):
    """A thread class that supports raising exception in the thread from
       another thread.
    """

    def _get_my_tid(self):
        """determines this (self's) thread id

        CAREFUL : this function is executed in the context of the caller
        thread, to get the identity of the thread represented by this
        instance.
        """
        if not self.is_alive():
            raise threading.ThreadError("the thread is not active")

        # do we have it cached?
        if hasattr(self, "_thread_id"):
            return self._thread_id

        # no, look for it in the _active dict
        for tid, tobj in threading._active.items():
            if tobj is self:
                self._thread_id = tid
                return tid

        raise AssertionError("could not determine the thread's id")

    def raise_exc(self, exctype):
        """Raises the given exception type in the context of this thread.

        If the thread is busy in a system call (time.sleep(),
        socket.accept(), ...), the exception is simply ignored.

        If you are sure that your exception should terminate the thread,
        one way to ensure that it works is:

            t = ThreadWithExc( ... )
            ...
            t.raiseExc( SomeException )
            while t.isAlive():
                time.sleep( 0.1 )
                t.raiseExc( SomeException )

        If the exception is to be caught by the thread, you need a way to
        check that your thread has caught it.

        CAREFUL : this function is executed in the context of the
        caller thread, to raise an excpetion in the context of the
        thread represented by this instance.
        """
        _async_raise(self._get_my_tid(), exctype)


class PostPythonModule(_PostCommonModule):
    """Viper本地执行python脚本的模块模板"""
    MODULE_BROKER = BROKER.post_python_job

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)  # 父类无需参数
        # 设置模块参数
        self.exit_flag = False

    # shellcode及exe相关函数
    def generate_hex_reverse_shellcode_by_handler(self):
        """通过监听配置生成shellcode"""
        handler_config = self.param(HANDLER_OPTION.get('name'))
        if handler_config is None:
            return None
        shellcode = Payload.generate_shellcode(mname=handler_config.get("PAYLOAD"), opts=handler_config)
        reverse_hex_str = shellcode.hex()[::-1]
        return reverse_hex_str

    # shellcode及exe相关函数
    def generate_hex_reverse_shellcode_array_by_handler(self):
        """通过监听配置生成shellcode"""
        handler_config = self.param(HANDLER_OPTION.get('name'))
        if handler_config is None:
            return None
        shellcode = Payload.generate_shellcode(mname=handler_config.get("PAYLOAD"), opts=handler_config)
        reverse_hex_str = shellcode.hex()[::-1]
        tmp = []
        for a in reverse_hex_str:
            tmp.append(f"'{a}'")
        reverse_hex_str_array = ",".join(tmp)
        return reverse_hex_str_array

    def run(self):
        """任务执行时框架会自动调用的函数,子类需要重新实现"""
        self.log_error("模块中未实现run函数", "The run function is not implemented in the module")

    def _thread_run(self):
        t1 = ThreadWithExc(target=self.run)
        t1.start()
        while True:
            req = Xcache.get_module_task_by_uuid(self._module_uuid)
            if req is None:  # 检查模块是否已经删除
                self.exit_flag = True
                time.sleep(3)
                while t1.is_alive():
                    time.sleep(0.1)
                    try:
                        t1.raise_exc(Exception)
                    except Exception as _:
                        pass
                break
            elif t1.is_alive() is not True:
                break
            else:
                time.sleep(1)


class PostMSFRawModule(_PostMSFModuleCommon):
    """调用原始msf模块的模板"""
    MODULE_BROKER = BROKER.post_msf_job

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)  # 传递参数,请勿移动此行代码

    def set_smb_info_by_credential(self):
        credential_record = self.param(CREDENTIAL_OPTION.get('name'))
        if credential_record is None:
            return False

        if credential_record.get('username') is not None:
            self.set_msf_option(key='SMBUser', value=credential_record.get('username'))
        else:
            return False

        if credential_record.get('password') is not None:
            self.set_msf_option(key='SMBPass', value=credential_record.get('password'))
        else:
            return False
        if credential_record.get('tag').get('domain') is not None:
            self.set_msf_option(key='SMBDomain', value=credential_record.get('tag').get('domain'))
        else:
            return True
        return True


class PostMSFCSharpModule(_PostMSFModuleCommon):
    """主机内存执行CSharp可执行文件的模块模板"""
    REQUIRE_SESSION = True
    PLATFORM = ["Windows"]  # 平台

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

        # 设置MSF模块的固定参数
        self.type = "post"  # 固定模块
        self.mname = "windows/manage/execute_assembly_module_api"  # 固定模块
        self.opts['SESSION'] = self._sessionid

    def set_assembly(self, assembly):
        """API:设置assembly文件名,不要加exe后缀"""
        self.opts['ASSEMBLY'] = str(assembly)

    def set_arguments(self, arguments):
        """API:设置命令行参数"""
        self.opts['ARGUMENTS'] = str(arguments)

    def set_execute_wait(self, wait_second):
        """API:执行后读取输出前的等待时间"""
        self.opts['WAIT'] = wait_second  # msf模块内部的超时时间

    def get_console_output(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
            return None
        else:
            assembly_out = base64.b64decode(data).decode('utf-8', errors="ignore")
            if assembly_out is None or len(assembly_out) == 0:
                self.log_warning("exe文件未输出信息", "exe file does not output information")
                if self.param("ARGUMENTS") is None or len(self.param("ARGUMENTS")) == 0:
                    self.log_warning("如果exe程序接受参数输入，请尝试输入参数",
                                     "If the exe program accepts parameter input, please try to enter the parameter")
                return assembly_out
            else:
                return assembly_out.replace("\nExecuteSharp end", "")


class PostMSFPowershellModule(_PostMSFModuleCommon):
    """主机内存执行powershell脚本模块模板"""
    REQUIRE_SESSION = True

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

        # 设置MSF模块的固定参数
        self.type = "post"  # 固定模块
        self.mname = "windows/manage/powershell/exec_powershell_mem"  # 固定模块
        self.opts['SESSION'] = self._sessionid

    def set_script(self, script):
        """API:设置脚本路径"""
        self.opts['SCRIPT'] = str(script)

    def set_script_timeout(self, timeout):
        """API:设置脚本超时时间"""
        self.opts['TIMEOUT'] = timeout  # msf模块内部的超时时间


class PostMSFPythonModule(_PostMSFModuleCommon):
    """主机内存执行python脚本的模块模板"""
    REQUIRE_SESSION = True

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

        # 设置MSF模块的固定参数
        self.type = "post"  # 固定模块
        self.mname = "multi/manage/exec_python"  # 固定模块
        self.opts['SESSION'] = self._sessionid

    def set_script(self, script):
        """API:设置脚本路径"""
        self.opts['SCRIPT'] = str(script)

    def set_script_timeout(self, timeout):
        """API:设置脚本超时时间"""
        self.opts['TIMEOUT'] = timeout  # msf模块内部的超时时间


class PostMSFPythonWithParamsModule(_PostMSFModuleCommon):
    """主机内存执行python脚本的模块模板(带参数)
    (注意在脚本中必须带有get_script_param函数)"""
    REQUIRE_SESSION = True

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

        # 设置MSF模块的必填参数
        self.type = "post"  # 固定模块
        self.mname = "multi/manage/exec_python_with_params_api"  # 固定模块
        self.opts['SESSION'] = self._sessionid
        self.opts['RESET_PYTHON'] = True
        # 设置脚本参数
        self.script_params = {}

    def set_script(self, script):
        """API:设置脚本路径"""
        self.opts['SCRIPT'] = str(script)

    def set_script_param(self, key, value):
        """设置脚本参数"""
        self.script_params[key] = value
        tmpstr = base64.b64encode(json.dumps(self.script_params).encode("utf-8")).decode("utf-8")
        self.opts['PARAMS'] = tmpstr

    def set_script_timeout(self, timeout):
        """API:设置脚本超时时间"""
        self.opts['TIMEOUT'] = timeout  # msf模块内部的超时时间


class PostMSFPowershellFunctionModule(_PostMSFModuleCommon):
    """主机内存加载加载powershell脚本后执行其中的函数的模块模板"""
    REQUIRE_SESSION = True

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

        # 设置MSF模块的必填参数
        self.type = "post"  # 固定模块
        self.mname = "windows/manage/powershell/exec_powershell_function_mem_api"
        self.opts['SESSION'] = self._sessionid

    def set_script(self, script):
        """API:设置脚本路径"""
        self.opts['SCRIPT'] = str(script)

    def set_largeoutput(self, flag):
        """API:设置是否为大量数据输出,因为读取文件问题 callback函数中需要调用output = output.replace('\x00', '')处理一下结果"""
        self.opts['LARGEOUTPUT'] = flag

    def set_execute_string(self, execute_string):
        """API:设置执行的函数及参数"""
        self.opts['EXECUTE_STRING'] = execute_string


class PostMSFExecPEModule(_PostMSFModuleCommon):
    """上传pe文件到主机并执行的模块模板"""
    REQUIRE_SESSION = True

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

        # 设置MSF模块的必填参数
        self.type = "post"
        self.mname = "multi/manage/upload_and_exec_api"
        self.opts['SESSION'] = self._sessionid

    def set_pepath(self, pepath):
        """API:设置pe文件路径"""
        self.opts['LPATH'] = str(pepath)

    def set_args(self, args):
        """API:设置pe文件执行参数"""
        self.opts['ARGS'] = str(args)
