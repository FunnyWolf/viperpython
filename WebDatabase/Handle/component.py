# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from elasticsearch_dsl import Search, Q

from Lib.configs import ES_MAX_COUNT
from Lib.esclient import EsClient
from WebDatabase.documents import ComponentDocument, IPDomainDocument


class Component(object):

    @staticmethod
    def list_by_ipdomain_port(ipdomain, port):
        bool_query = Q('bool', must=[
            Q('term', ipdomain=ipdomain),
            Q('term', port=port)
        ])
        response = Search(index=ComponentDocument.Index.name).query(bool_query).execute()
        data_dict = EsClient.convert_to_dicts(response)
        return data_dict

    @staticmethod
    def list_by_project_id(project_id):
        response = Search(index=ComponentDocument.Index.name).query('term', project_id=project_id).execute()
        data_dict = EsClient.convert_to_dicts(response)
        return data_dict

    @staticmethod
    def list_by_project_for_component(project_id):
        s = Search(index=IPDomainDocument.Index.name).query('term', project_id=project_id)
        s = s.extra(size=ES_MAX_COUNT)
        response = s.execute()
        ipdomains = [hit.ipdomain for hit in response]

        s = Search(index=ComponentDocument.Index.name).query('terms', ipdomain=ipdomains)
        s = s.extra(size=ES_MAX_COUNT)
        response = s.execute()
        product_names = []
        for hit in response:
            if hit.product_name not in product_names:
                product_names.append(hit.product_name)
        return product_names
