# -*- coding: utf-8 -*-
# @File  : servicestatus.py
# @Date  : 2021/2/25
# @Desc  :
from Lib.api import data_return
from Lib.configs import CODE_MSG_ZH, RPC_FRAMEWORK_API_REQ, CODE_MSG_EN
from Lib.log import logger
from Lib.method import Method
from Lib.rpcclient import RpcClient
from Lib.xcache import Xcache
from WebDatabase.Handle.worker import Worker


class ServiceStatus(object):
    """检查服务状态"""

    def __init__(self):
        pass

    @staticmethod
    def list():

        result = ServiceStatus.update_service_status()

        context = data_return(200, result, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        return context

    @staticmethod
    def update_service_status():
        data = {
            'json_rpc': {'status': False},
            'wafcheck': {'status': False},
        }

        # 检查msfrpc服务状态
        result = RpcClient.call(method=Method.CoreVersion, params=None, timeout=RPC_FRAMEWORK_API_REQ)

        if result is None:
            data['json_rpc'] = {'status': False}
            logger.warning("json_rpc服务无法连接,请确认!")
        else:
            if Xcache.get_msfrpc_alive():
                logger.info(f'json_rpc连接成功,msfrpc心跳正常')
                data['json_rpc'] = {'status': True}
            else:
                logger.warning(f'json_rpc连接成功,msfrpc心跳中断')
                data['json_rpc'] = {'status': False}

        flag = Worker.ping_wafcheck()
        data['wafcheck'] = {'status': flag}

        return data
