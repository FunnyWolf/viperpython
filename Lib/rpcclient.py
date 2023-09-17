# -*- coding: utf-8 -*-
# @File  : rpcclient.py
# @Date  : 2021/2/26
# @Desc  :
import json

import chardet
import requests

# 单例模式
from CONFIG import RPC_TOKEN, JSON_RPC_URL
from Lib.configs import RPC_SESSION_OPER_SHORT_REQ
from Lib.log import logger
from Lib.notice import Notice
from Lib.xcache import Xcache

req_session = requests.session()


class RpcClient(object):
    def __init__(self):
        pass

    @staticmethod
    def call(method=None, params=None, timeout=RPC_SESSION_OPER_SHORT_REQ):
        _headers = {
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {RPC_TOKEN}",
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
        except requests.Timeout as _:
            if not Xcache.get_msfrpc_alive():
                Notice.send_warning(f"MSFRPC服务心跳中断",
                                    "MSFRPC service abnormal")
                logger.warning(f'MSFRPC服务心跳中断')

            Notice.send_warning(f"MSFRPC请求执行超时",
                                "MSFRPC request execute timeout")
            logger.warning(f'json_data: {json_data}')
            return None
        except Exception as e:
            if not Xcache.get_msfrpc_alive():
                Notice.send_warning(f"MSFRPC服务心跳中断",
                                    "MSFRPC service abnormal")
                logger.warning(f'MSFRPC服务心跳中断')

            Notice.send_warning(f"MSFRPC服务请求异常",
                                "MSFRPC service connection failed, please check MSFRPC status")
            logger.warning(f'msf连接失败,检查 {JSON_RPC_URL} 不可用')
            logger.warning(f'json_data: {json_data}')
            logger.exception(e)
            return None
        if r.status_code == 200:
            data_bytes = r.content
            chardet_result = chardet.detect(data_bytes)
            try:
                data = data_bytes.decode(chardet_result['encoding'] or 'utf-8', 'ignore')
            except UnicodeDecodeError as e:
                data = data_bytes.decode('utf-8', 'ignore')

            try:
                content = json.loads(data)
            except json.decoder.JSONDecodeError as e:
                logger.error(e)
                logger.warning(data)
                return None

            if content.get('error') is not None:
                logger.warning(f"错误码:{content.get('error').get('code')} 信息:{content.get('error').get('message')}")
                Notice.send_exception(f"MSFRPC> {content.get('error').get('message')}",
                                      f"MSFRPC> {content.get('error').get('message')}")
                return None
            else:
                return content.get('result')

        else:
            logger.warning(f"返回码:{r.status_code} 结果:{r.content}")
            return None
