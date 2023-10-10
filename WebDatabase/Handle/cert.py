# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import CertModel


class Cert(object):

    @staticmethod
    def update_or_create(project_id=None, source=None, source_key=None, data={}, update_time=None,
                         ip=None, port=None,
                         cert=None, jarm=None, ):
        # 给出更新HttpCertModel方法
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

            'cert': cert,
            'jarm': jarm,
        }
        model, create = CertModel.objects.update_or_create(ip=ip, port=port, source=source,
                                                           defaults=default_dict)
        return create
