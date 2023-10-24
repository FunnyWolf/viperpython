# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import ScreenshotModel
from WebDatabase.serializers import ScreenshotSerializer


class Screenshot(object):
    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        if ScreenshotModel.objects.filter(ipdomain=ipdomain, port=port).count() == 0:
            return None

        model = ScreenshotModel.objects.get(ipdomain=ipdomain, port=port)
        result = ScreenshotSerializer(model, many=False).data
        return result

    @staticmethod
    def update_or_create(ipdomain=None, port=None,
                         content=None, webbase_dict={}):
        default_dict = {
            # 'ipdomain': ipdomain,
            # 'port': port,

            'content': content,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = ScreenshotModel.objects.update_or_create(ipdomain=ipdomain, port=port,
                                                                  defaults=default_dict)
        return created
