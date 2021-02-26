# -*- coding: utf-8 -*-
# @File  : serverchan.py
# @Date  : 2021/2/25
# @Desc  :
import json

import requests

from Lib.log import logger
from Lib.notice import Notice


class ServerChan(object):
    def __init__(self, sendkey=None):
        self.url = f"https://sctapi.ftqq.com/{sendkey}.send"
        self.headers = {"Content-type": "application/x-www-form-urlencoded"}

    def send_text(self, text=None):
        if text:
            pass
        else:
            return False

        msg = {'text': text, 'desp': text}
        r = requests.post(self.url, headers=self.headers, data=msg, timeout=3)
        if r.status_code == 200:
            content = json.loads(r.content.decode('utf-8', 'ignore'))
            if content.get('data').get('error') != "SUCCESS":
                logger.warning("ServerChan 消息发送失败,错误码:{} 错误消息:{}".format(content.get('code'), content.get('message')))
                Notice.send_alert(
                    "ServerChan 消息发送失败,错误码:{} 错误消息:{}".format(content.get('code'), content.get('message')))
                return False
            else:
                return True

        else:
            logger.warning("ServerChan 消息发送失败,HTTP状态码:{} 结果:{}".format(r.status_code, r.content))
            return False
