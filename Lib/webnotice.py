# -*- coding: utf-8 -*-
# @File  : notice.py
# @Date  : 2021/2/25
# @Desc  :
import time

from Lib.configs import CN, EN
from Lib.xcache import Xcache


class WebNotice(object):

    def __init__(self):
        pass

    @staticmethod
    def send(content_cn=None, content_en=None, level=1):
        if content_en is None:
            content_en = content_cn

        notice = {CN: content_cn, EN: content_en, "level": level, "time": int(time.time())}
        Xcache.add_one_web_notice(notice)
        return True

    @staticmethod
    def send_success(content_cn=None, content_en=None):
        """成功消息"""
        return WebNotice.send(content_cn, content_en, 0)

    @staticmethod
    def send_info(content_cn=None, content_en=None):
        """通知消息"""
        return WebNotice.send(content_cn, content_en)

    @staticmethod
    def send_warning(content_cn=None, content_en=None):
        """警告消息"""
        return WebNotice.send(content_cn, content_en, 2)

    @staticmethod
    def send_error(content_cn=None, content_en=None):
        """错误消息"""
        return WebNotice.send(content_cn, content_en, 3)

    @staticmethod
    def send_exception(content_cn=None, content_en=None):
        """异常消息"""
        return WebNotice.send(content_cn, content_en, 4)

    @staticmethod
    def send_alert(content_cn=None, content_en=None):
        """提醒消息"""
        return WebNotice.send(content_cn, content_en, 5)

    @staticmethod
    def list_notices():
        notices = Xcache.get_web_notices()
        return notices

    @staticmethod
    def clean_notices():
        flag = Xcache.clean_web_notices()
        return flag
