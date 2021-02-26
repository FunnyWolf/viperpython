# -*- coding: utf-8 -*-
# @File  : rpcclient.py
# @Date  : 2021/2/26
# @Desc  :
import json

import requests

# 单例模式
from CONFIG import RPC_TOKEN, JSON_RPC_URL
from Lib.log import logger
from Lib.notice import Notice

req_session = requests.session()


class RpcClient(object):
    def __init__(self):
        pass

    @staticmethod
    def call(method=None, params=None, timeout=11):
        _headers = {
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Authorization': "Bearer {}".format(RPC_TOKEN),
        }

        data = {'jsonrpc': '2.0', 'id': 1, 'method': method}

        if params is not None:
            if isinstance(params, list):
                data['params'] = params
            else:
                logger.warning("params 必须是list类型")
                return None
        json_data = json.dumps(data)
        try:
            r = req_session.post(JSON_RPC_URL, headers=_headers, data=json_data, timeout=(1.05, timeout))
        except Exception as _:
            logger.warning('msf连接失败,检查 {} 是否可用'.format(JSON_RPC_URL))
            return None
        if r.status_code == 200:
            content = json.loads(r.content.decode('utf-8', 'ignore'))
            if content.get('error') is not None:
                logger.warning(
                    "错误码:{} 信息:{}".format(content.get('error').get('code'), content.get('error').get('message')))
                Notice.send_exception(f"MSFRPC> {content.get('error').get('message')}")
                return None
            else:
                return content.get('result')

        else:
            logger.warning("返回码:{} 结果:{}".format(r.status_code, r.content))
            return None
