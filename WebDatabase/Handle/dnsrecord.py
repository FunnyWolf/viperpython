# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import DNSRecordModel
from WebDatabase.serializers import DNSRecordSerializer


class DNSRecord(object):

    @staticmethod
    def get_by_ipdomain(ipdomain):
        if DNSRecordModel.objects.filter(ipdomain=ipdomain).count() == 0:
            return None

        model = DNSRecordModel.objects.get(ipdomain=ipdomain)
        result = DNSRecordSerializer(model, many=False).data
        return result

    @staticmethod
    def update_or_create(domain=None, a=[], cname=[], webbase_dict={}):
        # 给出更新DomainICPModel的方法

        default_dict = {
            'a': a,
            'cname': cname,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = DNSRecordModel.objects.update_or_create(ipdomain=domain,
                                                                 defaults=default_dict)
        return created
