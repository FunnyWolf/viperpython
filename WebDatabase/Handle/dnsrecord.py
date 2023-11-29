# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import DNSRecordModel
from WebDatabase.serializers import DNSRecordSerializer


class DNSRecord(object):

    @staticmethod
    def list_by_ipdomain(ipdomain):
        models = DNSRecordModel.objects.filter(ipdomain=ipdomain)
        records = DNSRecordSerializer(models, many=True).data
        result = []
        for one_record in records:
            for one_value in one_record.get('value'):
                result.append({"type": one_record.get('type'), "value": one_value})
        return result

    @staticmethod
    def update_or_create(domain=None, type=None, value: list = None, webbase_dict={}):
        # 给出更新DomainICPModel的方法

        default_dict = {
            'type': type,
            'value': value,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据

        model, created = DNSRecordModel.objects.update_or_create(ipdomain=domain,
                                                                 type=type,
                                                                 defaults=default_dict)
        return created

    @staticmethod
    def get_by_ipdomain(ipdomain):
        model = DNSRecordModel.objects.filter(ipdomain=ipdomain).first()
        if not model:
            return None
        result = DNSRecordSerializer(model).data
        return result

    @staticmethod
    def get_domain_first_ip(domain):
        model = DNSRecordModel.objects.filter(ipdomain=domain, type="A").first()
        if not model:
            return None
        result = DNSRecordSerializer(model).data
        a = result.get("value")
        return a[0]
