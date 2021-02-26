# -*- coding: utf-8 -*-
# @File  : notice.py
# @Date  : 2021/2/25
# @Desc  :
import time

from Lib.configs import VIPER_SEND_SMS_CHANNEL
from Lib.log import logger
from Lib.redisclient import RedisClient
from Lib.xcache import Xcache


class Notice(object):

    def __init__(self):
        pass

    @staticmethod
    def send(content, level=1):
        notice = {"content": content, "level": level, "time": int(time.time())}
        Xcache.add_one_notice(notice)
        return True

    @staticmethod
    def send_success(content):
        """成功消息"""
        return Notice.send(content, 0)

    @staticmethod
    def send_info(content):
        """通知消息"""
        return Notice.send(content)

    @staticmethod
    def send_warning(content):
        """警告消息"""
        return Notice.send(content, 2)

    @staticmethod
    def send_warn(content):
        """警告消息"""
        return Notice.send(content, 2)

    @staticmethod
    def send_error(content):
        """错误消息"""
        return Notice.send(content, 3)

    @staticmethod
    def send_exception(content):
        """异常消息"""
        return Notice.send(content, 4)

    @staticmethod
    def send_alert(content):
        """提醒消息"""
        return Notice.send(content, 5)

    @staticmethod
    def send_userinput(content, userkey="0"):
        """用户输入消息"""
        notice = {"content": content, "level": 6, "time": int(time.time()), "userkey": userkey}
        Xcache.add_one_notice(notice)
        return notice

    @staticmethod
    def list_notices():
        notices = Xcache.get_notices()
        return notices

    @staticmethod
    def clean_notices():
        flag = Xcache.clean_notices()
        return flag

    @staticmethod
    def send_sms(content):
        rcon = RedisClient.get_result_connection()
        if rcon is None:
            return
        result = rcon.publish(VIPER_SEND_SMS_CHANNEL, content)
        logger.info(f"send_sms: {result}")
