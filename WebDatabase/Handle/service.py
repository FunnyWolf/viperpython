# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from elasticsearch_dsl import Search

from Lib.configs import ES_MAX_COUNT
from Lib.esclient import EsClient
from WebDatabase.documents import ServiceDocument, IPDomainDocument


# s.aggs.bucket('field_values', 'terms', field='ipdomain')
# response = s.execute()

class Service(object):
    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        doc = ServiceDocument(ipdomain=ipdomain, port=port)
        return doc.get_dict()

    @staticmethod
    def list_by_project_and_service(project_id, service=None):
        s = Search(index=IPDomainDocument.Index.name).query('term', project_id=project_id)
        s = s.extra(size=ES_MAX_COUNT)
        response = s.execute()
        ipdomains = [hit.ipdomain for hit in response]
        if service:
            s = ServiceDocument.search()
            s = s.filter('term', service=service)
            s = s.filter('terms', ipdomain=ipdomains)
            s = s.extra(size=ES_MAX_COUNT)
            response = s.execute()
            data_dict = EsClient.convert_to_dicts(response)
            return data_dict
        else:
            s = Search(index=ServiceDocument.Index.name).query('terms', ipdomain=ipdomains)
            s = s.extra(size=ES_MAX_COUNT)
            response = s.execute()
            services = []
            for hit in response:
                if hit.service not in services:
                    services.append(hit.service)
            return services
