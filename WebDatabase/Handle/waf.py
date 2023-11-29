# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import WAFModel
from WebDatabase.serializers import WAFSerializer


class WAF(object):

    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        model = WAFModel.objects.filter(ipdomain=ipdomain, port=port).first()
        if not model:
            return None
        result = WAFSerializer(model, many=False).data
        return result

    @staticmethod
    def update_or_create(ipdomain=None, port=None, flag=None, trigger_url=None, name=None, manufacturer=None,
                         webbase_dict={}):
        default_dict = {
            'flag': flag,
            'trigger_url': trigger_url,
            'name': name,
            'manufacturer': manufacturer,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据

        model, created = WAFModel.objects.update_or_create(ipdomain=ipdomain, port=port,
                                                           defaults=default_dict)
        return created
