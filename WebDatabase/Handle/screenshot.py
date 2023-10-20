# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import ScreenshotModel


class Screenshot(object):

    @staticmethod
    def update_or_create(ip=None, port=None,
                         content=None, webbase_dict={}):
        default_dict = {
            'ip': ip,
            'port': port,

            'content': content,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = ScreenshotModel.objects.update_or_create(ip=ip, port=port,
                                                                  defaults=default_dict)
        return created
