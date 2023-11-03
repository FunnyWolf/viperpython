# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from Lib.log import logger
from WebDatabase.models import HttpFaviconModel
from WebDatabase.serializers import HttpFaviconSerializer


class HttpFavicon(object):

    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        try:
            model = HttpFaviconModel.objects.filter(ipdomain=ipdomain, port=port).first()
            result = HttpFaviconSerializer(model, many=False).data
            return result
        except Exception as E:
            logger.exception(E)
            return None

    @staticmethod
    def update_or_create(ipdomain=None, port=None, content=None, hash=None, webbase_dict={}):
        default_dict = {
            # 'ipdomain': ipdomain,
            # 'port': port,

            'content': content,
            'hash': hash,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = HttpFaviconModel.objects.update_or_create(ipdomain=ipdomain, port=port, defaults=default_dict)
        return created
