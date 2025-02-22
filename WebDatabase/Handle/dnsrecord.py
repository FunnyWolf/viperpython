# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from elasticsearch_dsl import Search, Q

from Lib.esclient import EsClient
from WebDatabase.documents import DNSRecordDocument


class DNSRecord(object):

    @staticmethod
    def list_by_ipdomain(ipdomain):
        response = Search(index=DNSRecordDocument.Index.name).query('term', ipdomain=ipdomain).execute()
        data_dict = EsClient.convert_to_dicts(response)
        result = []
        for one_record in data_dict:
            for one_value in one_record.get('value'):
                result.append({"type": one_record.get('type'), "value": one_value})
        return result

    # @staticmethod
    # def get_cname_by_ipdomain(ipdomain):
    #     models = DNSRecordModel.objects.filter(ipdomain=ipdomain)
    #     records = DNSRecordSerializer(models, many=True).data
    #     result = []
    #     for one_record in records:
    #         if one_record.get('type') == 'CNAME':
    #             result.extend(one_record.get('value'))
    #     return result

    # @staticmethod
    # def update_or_create(domain=None, type=None, value: list = None, webbase_dict={}):
    #     # 给出更新DomainICPModel的方法
    #
    #     default_dict = {
    #         'type': type,
    #         'value': value,
    #     }
    #     default_dict.update(webbase_dict)
    #     # key + source 唯一,只要最新数据
    #
    #     model, created = DNSRecordModel.objects.update_or_create(ipdomain=domain,
    #                                                              type=type,
    #                                                              defaults=default_dict)
    #     return created

    # @staticmethod
    # def get_by_ipdomain(ipdomain):
    #     model = DNSRecordModel.objects.filter(ipdomain=ipdomain).first()
    #     if not model:
    #         return None
    #     result = DNSRecordSerializer(model).data
    #     return result

    @staticmethod
    def get_domain_first_ip(domain):
        bool_query = Q('bool', must=[
            Q('term', domain=domain),
            Q('term', type="A")
        ])

        response = Search(index=DNSRecordDocument.Index.name).query(bool_query).execute()
        data_dict = EsClient.convert_to_dicts(response)
        if not data_dict:
            return None
        result = data_dict[0]
        a = result.get("value")
        return a[0]

    # @staticmethod
    # def delete_by_ipdomain(ipdomain):
    #     DNSRecordModel.objects.filter(ipdomain=ipdomain).delete()

# class DNSRecordObject(IPDomainBaseObject, WebBaseObject, ConfigBaseObject):
#     def __init__(self):
#         super().__init__()
#         self.type = None
#         self.value = []
#
#     def update_or_create(self):
#         default_dict = {
#             'ipdomain': self.ipdomain,
#             'type': self.type,
#             'value': self.value,
#
#             'source': self.source,
#             'update_time': self.update_time,
#             'data': self.data,
#         }
#         model, created = DNSRecordModel.objects.update_or_create(ipdomain=self.ipdomain,
#                                                                  type=self.type,
#                                                                  defaults=default_dict)
#         return model
