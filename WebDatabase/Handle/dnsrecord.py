# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import DNSRecordModel


class DNSRecord(object):

    @staticmethod
    def update_or_create(ip=None, domain=None, type=None, value=None, webbase_dict={}):
        # 给出更新DomainICPModel的方法

        default_dict = {
            'ip': ip,
            'domain': domain,
            'type': type,
            'value': value,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = DNSRecordModel.objects.update_or_create(ip=ip, domain=domain, type=type,
                                                                 defaults=default_dict)
        return created
