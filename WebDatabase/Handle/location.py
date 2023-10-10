# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import LocationModel


class Location(object):

    @staticmethod
    def update_or_create(project_id=None, source=None, source_key=None, data={}, update_time=None,
                         ip=None, isp=None, asname=None, geo_info={}, ):
        if update_time is None:
            update_time = 0

        default_dict = {
            'project_id': project_id,
            'source': source,
            "source_key": source_key,
            'data': data,
            'update_time': update_time,
            'ip': ip,

            'isp': isp,
            'asname': asname,
            'geo_info': geo_info,
        }

        # key + source 唯一,只要最新数据
        model, created = LocationModel.objects.update_or_create(ip=ip, source=source, defaults=default_dict)
        return created
