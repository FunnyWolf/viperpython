# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import ComponentModel


class Component(object):

    @staticmethod
    def update_or_create(ip=None, port=None,
                         product_dict_values={}, product_type=[], product_catalog=[], webbase_dict={}):
        default_dict = {
            'ip': ip,
            'port': port,

            'product_dict_values': product_dict_values,
            'product_type': product_type,
            'product_catalog': product_catalog,
        }
        default_dict.update(webbase_dict)
        model, create = ComponentModel.objects.update_or_create(ip=ip, port=port,
                                                                product_dict_values=product_dict_values,
                                                                defaults=default_dict)
        return create
