# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import PortServiceModel
from WebDatabase.serializers import PortServiceSerializer


class PortService(object):

    @staticmethod
    def list_by_ip(ip):
        models = PortServiceModel.objects.filter(ip=ip)
        result = PortServiceSerializer(models, many=True).data
        return result

    @staticmethod
    def sort_by_port(a, b):
        if a['port'] < b['port']:
            return 1
        elif b['port'] > a['port']:
            return -1
        else:
            return 0

    @staticmethod
    def update_or_create(ip=None, port=None, transport=None, service=None, version=None, webbase_dict={}):
        # 给出更新PortServiceModel方法

        default_dict = {
            'ip': ip,
            'port': port,

            'transport': transport,
            'service': service,
            'version': version,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = PortServiceModel.objects.update_or_create(ip=ip, port=port,
                                                                   defaults=default_dict)
        return created
