# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import PortServiceModel
from WebDatabase.serializers import PortServiceSerializer


class PortService(object):

    @staticmethod
    def list_by_ipdomain(ipdomain):
        models = PortServiceModel.objects.filter(ipdomain=ipdomain)
        result = PortServiceSerializer(models, many=True).data
        return result

    # portservices_sorted = sorted(port_and_service, key=lambda x: x['port'])
    @staticmethod
    def sort_by_port(a, b):
        if a['port'] < b['port']:
            return 1
        elif b['port'] > a['port']:
            return -1
        else:
            return 0

    @staticmethod
    def update_or_create(ipdomain=None, port=None, transport=None, service=None, version=None, webbase_dict={}):
        # 给出更新PortServiceModel方法

        default_dict = {
            # 'ipdomain': ipdomain,
            # 'port': port,

            'transport': transport,
            'service': service,
            'version': version,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = PortServiceModel.objects.update_or_create(ipdomain=ipdomain, port=port,
                                                                   defaults=default_dict)
        return created
