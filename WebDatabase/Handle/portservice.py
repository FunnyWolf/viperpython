# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import PortServiceModel


class PortService(object):

    @staticmethod
    def update_or_create(project_id=None, source=None, source_key=None, data={}, update_time=None,
                         ip=None, port=None,
                         transport=None, service=None, version=None, ):
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

            'transport': transport,
            'service': service,
            'version': version,
        }

        # key + source 唯一,只要最新数据
        model, created = PortServiceModel.objects.update_or_create(ip=ip, port=port, source=source,
                                                                   defaults=default_dict)
        return created
