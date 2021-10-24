# -*- coding: utf-8 -*-
# @File  : msfmodule.py
# @Date  : 2019/3/15
# @Desc  :


from Lib.configs import RPC_JOB_API_REQ, RPC_RUN_MODULE_LONG
from Lib.method import Method
from Lib.rpcclient import RpcClient


class MsfModule(object):
    """msf模块类"""

    def __init__(self):
        pass

    @staticmethod
    def run_with_output(module_type, mname, opts, timeout=RPC_RUN_MODULE_LONG):
        """实时运行,获取输出"""
        params = [module_type,
                  mname,
                  opts,
                  False,
                  timeout]
        result = RpcClient.call(Method.ModuleExecute, params, timeout=timeout)
        return result

    @staticmethod
    def run_as_job(module_type, mname, opts):
        """后台任务方式运行"""
        params = [module_type,
                  mname,
                  opts,
                  True,
                  RPC_JOB_API_REQ]
        result = RpcClient.call(Method.ModuleExecute, params, timeout=RPC_JOB_API_REQ)
        return result
