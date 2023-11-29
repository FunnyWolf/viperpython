# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import ComponentModel
from WebDatabase.serializers import ComponentSerializer


class Component(object):

    @staticmethod
    def list_by_ipdomain_port(ipdomain, port):
        models = ComponentModel.objects.filter(ipdomain=ipdomain, port=port)
        result = ComponentSerializer(models, many=True).data
        return result

    @staticmethod
    def update_or_create(ipdomain=None, port=None, product_name=None, product_version=None,
                         product_type=[], product_catalog=[], product_dict_values={}, webbase_dict={}):
        default_dict = {
            # 'ipdomain': ipdomain,
            # 'port': port,
            'product_name': product_name,
            'product_version': product_version,
            'product_dict_values': product_dict_values,
            'product_type': product_type,
            'product_catalog': product_catalog,
        }
        default_dict.update(webbase_dict)

        model, create = ComponentModel.objects.update_or_create(ipdomain=ipdomain, port=port,
                                                                product_name=product_name,
                                                                defaults=default_dict)
        return create
