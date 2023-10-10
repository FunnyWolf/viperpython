# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import ComponentModel


class Component(object):

    @staticmethod
    def update_or_create(project_id=None, source=None, source_key=None, data={}, update_time=None,
                         ip=None, port=None,
                         product_dict_values={}, product_type=[], product_catalog=[]):
        # 给出更新PortServiceModel方法
        if update_time is None:
            update_time = 0

        default_dict = {
            'project_id': project_id,
            'source': source,
            "source_key": source_key,
            'data': data,
            'update_time': update_time,

            'ip': ip,
            'port': port,

            'product_dict_values': product_dict_values,
            'product_type': product_type,
            'product_catalog': product_catalog,

        }
        model, create = ComponentModel.objects.update_or_create(ip=ip, port=port, source=source,
                                                                product_dict_values=product_dict_values,
                                                                defaults=default_dict)
        return create
