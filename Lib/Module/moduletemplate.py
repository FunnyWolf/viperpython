# -*- coding: utf-8 -*-
# @File  : moduletemplate.py
# @Date  : 2019/1/11
# @Desc  :


import base64
import ctypes
import inspect
import json
import os
import re
import shutil
import threading
import time

from ipaddr import summarize_address_range, IPv4Network, IPv4Address

from Core.Handle.host import Host
from Lib.Module.configs import BROKER, TAG2CH, FILE_OPTION, HANDLER_OPTION, CACHE_HANDLER_OPTION, CREDENTIAL_OPTION
from Lib.lib import TMP_DIR
from Lib.log import logger
from Lib.xcache import Xcache
from Msgrpc.Handle.filemsf import FileMsf
from Msgrpc.Handle.handler import Handler
from PostLateral.Handle.credential import Credential
from PostLateral.Handle.portservice import PortService
from PostLateral.Handle.vulnerability import Vulnerability


class _CommonModule(object):
    MODULE_BROKER = BROKER.empty
    NAME = "基础模块"
    DESC = "基础描述"
    AUTHOR = "NoOne"  # 模块作者
    REFERENCES = []
    WARN = None  # 警告信息

    MODULETYPE = TAG2CH.example  # 模块类型

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
        self._hid = None  # 补齐默认参数,为了Serializer
        self._sessionid = None  # 补齐默认参数,为了Serializer
        self._ip = None  # 补齐默认参数,为了Serializer
        self._port = None  # 补齐默认参数,为了Serializer
        self._protocol = None  # 补齐默认参数,为了Serializer
        self.opts = {}

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
        return None

    # 模块参数
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
                return None

        else:
            return self._custom_param.get(name)

    @property
    def target_str(self):
        if self._sessionid is not None and self._sessionid != -1:
            return f"SID: {self._sessionid}"
        elif self._hid is not None and self._hid != -1:
            return f"IP: {self.host_ipaddress}"
        elif self._ip is not None:
            return f"IP: {self.host_ipaddress}"
        else:
            return ""

    def add_portservice(self, hid, port, proxy=None, banner=None, service=""):
        if proxy is None:
            proxy = {}
        if banner is None:
            banner = {}

        # 数据类型检查
        if isinstance(proxy, dict) is not True:
            logger.warning('数据类型检查错误,数据 {}'.format(proxy))
            proxy = {}
        if isinstance(banner, dict) is not True:
            logger.warning('数据类型检查错误,数据 {}'.format(banner))
            banner = {}
        result = PortService.add_or_update(hid=hid, port=port, proxy=proxy, banner=banner, service=service)
        return result

    def add_credential(self, username='', password='', password_type='', tag=None, desc=''):
        if tag is None:
            tag = {}
        if isinstance(tag, dict) is not True:
            logger.warning('数据类型检查错误,数据 {}'.format(tag))
            tag = {}
        if password is '' or password.find('n.a.(') > 0 or len(password) > 100:
            return False

        result = Credential.add_or_update(username, password, password_type, tag, self.NAME, self.host_ipaddress,
                                          desc)
        return result

    def add_vulnerability(self, hid_or_ipaddress=None, extra_data=None, desc=''):
        if extra_data is None:
            extra_data = {}
        if isinstance(extra_data, dict) is not True:
            logger.warning('数据类型检查错误,数据 {}'.format(extra_data))
            extra_data = {}
        if isinstance(hid_or_ipaddress, int):
            result = Vulnerability.add_or_update(hid_or_ipaddress, self.loadpath, extra_data, desc)
            return result
        elif isinstance(hid_or_ipaddress, str):
            result = Vulnerability.add_or_update(Host.get_by_ipaddress(hid_or_ipaddress).get('id'),
                                                 self.loadpath,
                                                 extra_data, desc)
            return result

    def add_host(self, ipaddress):
        result = Host.create_host(ipaddress)
        hid = result.get('id')
        return hid

    # 存储结果函数集
    def clean_log(self):
        flag = Xcache.set_module_result(self.host_ipaddress, self.loadpath, "")
        return flag

    def store_log(self, result_format):
        """API:存储结果到数据库"""
        result_format = result_format.strip()
        Xcache.set_module_result(self.host_ipaddress, self.loadpath, result_format)

    def log_raw(self, result_line):
        if not result_line.endswith('\n'):
            result_line = "{}\n".format(result_line)
        Xcache.add_module_result(self.host_ipaddress, self.loadpath, result_line)

    def log_status(self, result_line):
        result_format = "[*] {} \n".format(result_line)
        Xcache.add_module_result(self.host_ipaddress, self.loadpath, result_format)

    def log_good(self, result_line):
        result_format = "[+] {} \n".format(result_line)
        Xcache.add_module_result(self.host_ipaddress, self.loadpath, result_format)

    def log_warning(self, result_line):
        result_format = "[!] {} \n".format(result_line)
        Xcache.add_module_result(self.host_ipaddress, self.loadpath, result_format)

    def log_error(self, result_line):
        result_format = "[-] {} \n".format(result_line)
        Xcache.add_module_result(self.host_ipaddress, self.loadpath, result_format)

    def log_except(self, result_line):
        result_format = "[x] {} \n".format(result_line)
        Xcache.add_module_result(self.host_ipaddress, self.loadpath, result_format)

    def _store_result_in_history(self):
        # 特殊处理
        if self.MODULETYPE in [TAG2CH.internal]:
            return None
        opts = {}
        for key in self._custom_param:
            for option in self.OPTIONS:
                if option.get("name") == key:
                    if self._custom_param.get(key) is None:
                        continue
                    opts[option.get("name_tag")] = self._custom_param.get(key)

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

                            opts[option.get("name_tag")] = json.dumps(new_params)
                        elif key == FILE_OPTION.get("name"):
                            file_dict = json.loads(self._custom_param.get(key))
                            opts[option.get("name_tag")] = json.dumps({
                                "name": file_dict.get("name"),
                            })
                        elif key == CREDENTIAL_OPTION.get("name"):
                            credential_dict = json.loads(self._custom_param.get(key))
                            opts[option.get("name_tag")] = json.dumps({
                                "username": credential_dict.get("username"),
                                "password": credential_dict.get("password"),
                                "password_type": credential_dict.get("password_type"),
                            })
                    except Exception as E:
                        logger.exception(E)
        module_result = Xcache.get_module_result(ipaddress=self.host_ipaddress,
                                                 loadpath=self.__module__)

        flag = Xcache.add_module_result_history(ipaddress=self.host_ipaddress,
                                                loadpath=self.__module__,
                                                opts=opts,
                                                update_time=module_result.get("update_time"),
                                                result=module_result.get("result"))
        return flag

    # 功能函数集
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

    @staticmethod
    def timestamp_to_str(timestamp):
        """将时间戳转换为字符串."""
        time_array = time.localtime(timestamp)
        other_style_time = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
        return other_style_time

    @staticmethod
    def clean_tmp_dir():
        shutil.rmtree(TMP_DIR)
        os.mkdir(TMP_DIR)
        return True

    def get_option_filepath(self, msf=False):
        """获取选项中的文件名"""
        file = self.param(FILE_OPTION.get('name'))
        if file is None:
            return None

        file_path = FileMsf.get_absolute_path(file.get("name"), msf)
        if file_path is None:
            self.log_error("非docker部署不支持此模块,请使用原版donut工具")
            return None
        else:
            return file_path

    def get_option_fileinfo(self):
        """获取选项中的文件名"""
        fileinfo = self.param(FILE_OPTION.get('name'))
        return fileinfo

    def get_option_filename(self):
        """获取选项中的文件名"""
        fileinfo = self.get_option_fileinfo()
        if fileinfo is None:
            return None
        else:
            filename = self.param(FILE_OPTION.get('name')).get("name")
            return filename

    def set_payload_by_handler(self):
        """通过handler参数设置msf模块的payload"""
        handler_config = self.param(HANDLER_OPTION.get('name'))
        if handler_config is None:
            return False
        z = self.opts.copy()
        z.update(handler_config)
        z['disablepayloadhandler'] = True
        self.opts = z
        return True

    def cache_handlerconfig_for_persistence(self):

        if self.param(CACHE_HANDLER_OPTION.get("name")):
            handler_config = self.param(HANDLER_OPTION.get('name'))
            if handler_config is None:
                return False
            handler_config["HandlerName"] = f"用于: {self.NAME} IP: {self.host_ipaddress}"
            Handler.create_virtual_handler(handler_config)
            self.log_good("监听配置已缓存")
            return True
        else:
            return False

    def get_handler_payload(self):
        """通过handler参数获取msf模块的payload"""
        handler_config = self.param(HANDLER_OPTION.get('name'))
        if handler_config is None:
            return None
        else:
            payload = handler_config.get("PAYLOAD")
            return payload


class _BotCommonModule(_CommonModule):
    """bot模块基础模板"""

    def __init__(self, ip, port, protocol, custom_param):
        super().__init__(custom_param)  # 父类无需入参

        # 设置内部参数
        self._ip = ip  # 前端传入的ip地址
        self._port = port  # 前端传入的端口信息
        self._protocol = protocol  # 前端传入的协议类型
        self._custom_param = custom_param  # 前端传入的参数信息

    @property
    def host_ipaddress(self):
        return self._ip


class BotMSFModule(_BotCommonModule):
    """bot msf模块基础模板"""
    MODULE_BROKER = BROKER.bot_msf_job
    SEARCH = ''

    def __init__(self, ip, port, protocol, custom_param):
        super().__init__(ip, port, protocol, custom_param)  # 父类无需入参

        # 设置模块参数
        self.type = None  # msf模块类型
        self.mname = None  # msf模块路径
        self.opts = {}  # 设置MSF模块的必填参数

    def set_option(self, key, value):
        """设置msf模块参数"""
        self.opts[key] = value  # msf模块参数

    def callback(self, status, message, data):
        """后台运行模块回调函数"""
        logger.warning(self.type)
        logger.warning(self.mname)
        logger.warning(self.opts)


class _PostCommonModule(_CommonModule):
    """post类模块基础模板"""
    MODULE_BROKER = BROKER.post_msf_job

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(custom_param)  # 父类无需入参
        # 设置内部参数
        self._hid = hid  # 前端传入的hid信息
        self._sessionid = sessionid  # 前端传入的sessionid
        self._ipaddress = Host.get_ipaddress_by_hid(self._hid)

    @property
    def host_ipaddress(self):
        return self._ipaddress

    def param_address_range(self, name="address_range"):
        raw_input = self._custom_param.get(name)

        try:
            raw_lines = raw_input.split(",")
        except Exception as E:
            print(E)
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
                    print(E)
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

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)  # 父类无需入参

        # 设置MSF模块参数
        self.type = None  # msf模块类型
        self.mname = None  # msf模块路径
        self.opts = {'SESSION': self._sessionid}  # 设置MSF模块的必填参数

    def set_option(self, key, value):
        """设置msf模块参数"""
        self.opts[key] = value  # msf模块参数

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
    """多模块执行的基础模板"""
    MODULE_BROKER = BROKER.post_python_job

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)  # 父类无需参数

        # 设置模块参数
        self.module_self_uuid = None  # 为了存储uuid设置的字段
        self.exit_flag = False

    def run(self):
        """任务执行时框架会自动调用的函数,子类需要重新实现"""
        self.log_error("module has no function run")

    def thread_run(self):
        t1 = ThreadWithExc(target=self.run)
        t1.start()
        while True:
            req = Xcache.get_module_task_by_uuid_nowait(self.module_self_uuid)
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


# 后台运行模板
class PostMSFRawModule(_PostMSFModuleCommon):
    """调用原始msf模块的模板模块"""
    MODULE_BROKER = BROKER.post_msf_job

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)  # 传递参数,请勿移动此行代码

    def set_smb_info_by_credential(self):
        credential_record = self.param(CREDENTIAL_OPTION.get('name'))
        if credential_record is None:
            return False

        if credential_record.get('username') is not None:
            self.set_option(key='SMBUser', value=credential_record.get('username'))
        else:
            return False

        if credential_record.get('password') is not None:
            self.set_option(key='SMBPass', value=credential_record.get('password'))
        else:
            return False
        if credential_record.get('tag').get('domain') is not None:
            self.set_option(key='SMBDomain', value=credential_record.get('tag').get('domain'))
        else:
            return True
        return True


class PostMSFPowershellModule(_PostMSFModuleCommon):
    """直接调用powershell脚本执行的模板模块"""
    REQUIRE_SESSION = True

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)

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
    """调用python脚本的模板模块"""
    REQUIRE_SESSION = True

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)

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
    """调用python脚本(带参数)的模板模块(注意在脚本中必须带有get_script_param函数,可参考)"""
    REQUIRE_SESSION = True

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)

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
        tmpstr = base64.b64encode(bytes(json.dumps(self.script_params), encoding="utf8")).decode('ascii')
        self.opts['PARAMS'] = tmpstr

    def set_script_timeout(self, timeout):
        """API:设置脚本超时时间"""
        self.opts['TIMEOUT'] = timeout  # msf模块内部的超时时间


class PostMSFPowershellFunctionModule(_PostMSFModuleCommon):
    """模块用于加载powershell脚本后执行其中的函数的模板模块"""
    REQUIRE_SESSION = True

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)

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
        self.opts['EXECUTE_STRING'] = "{}".format(execute_string)


class PostMSFExecPEModule(_PostMSFModuleCommon):
    """直接调用powershell脚本执行的模板模块"""
    REQUIRE_SESSION = True

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)

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
