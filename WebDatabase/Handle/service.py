# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import ServiceModel
from WebDatabase.serializers import ServiceSerializer


class Service(object):

    @staticmethod
    def list_by_ipdomain_and_filter(ipdomain, port):
        models = ServiceModel.objects.filter(ipdomain=ipdomain)
        if port:
            models = models.filter(port=port)
        result = ServiceSerializer(models, many=True).data
        return result

    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        model = ServiceModel.objects.filter(ipdomain=ipdomain, port=port).first()
        if not model:
            return None
        result = ServiceSerializer(model).data
        return result

    @staticmethod
    def update_or_create(ipdomain=None, port=None, response=None,
                         response_hash=None, transport=None, service=None, version=None, webbase_dict={}):
        # 给出更新PortServiceModel方法

        default_dict = {
            # 'ipdomain': ipdomain,
            # 'port': port,
            'response': response,
            'response_hash': response_hash,
            'transport': transport,
            'service': service,
            'version': version,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = ServiceModel.objects.update_or_create(ipdomain=ipdomain, port=port,
                                                               defaults=default_dict)
        return created
