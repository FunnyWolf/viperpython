# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from Lib.log import logger
from WebDatabase.models import DNSRecordModel
from WebDatabase.serializers import DNSRecordSerializer


class DNSRecord(object):

    @staticmethod
    def list_by_ipdomain(ipdomain):
        try:
            models = DNSRecordModel.objects.filter(ipdomain=ipdomain)
            records = DNSRecordSerializer(models, many=True).data
            result = []
            for one_record in records:
                for one_value in one_record.get('value'):
                    result.append({"type": one_record.get('type'), "value": one_value})
            return result
        except Exception as E:
            logger.exception(E)
            return Nones

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