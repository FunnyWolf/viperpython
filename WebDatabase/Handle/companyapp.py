from elasticsearch_dsl import Search, Q

from Lib.esclient import EsClient
from WebDatabase.documents import CompanyAPPDocument


class CompanyAPP(object):
    @staticmethod
    def list_by_project_id(project_id):
        response = Search(index=CompanyAPPDocument.Index.name).query('term', project_id=project_id).execute()
        data_dict = EsClient.convert_to_dicts(response)
        return data_dict

    @staticmethod
    def destory_by_company_name_and_name(company_name, name):
        bool_query = Q('bool', must=[
            Q('term', company_name=company_name),
            Q('term', name=name)
        ])
        response = Search(index=CompanyAPPDocument.Index.name).query(bool_query).delete()
        return response.deleted

    @staticmethod
    def destory_by_name(name):
        response = Search(index=CompanyAPPDocument.Index.name).query('term', name=name).delete()
        return response.deleted

# class CompanyAPPObject(ProjectBaseObject, WebBaseObject, ConfigBaseObject):
#
#     def __init__(self):
#         super().__init__()
#         self.company_name = None
#         self.pid = None
#         self.name = None
#         self.classify = None
#         self.logo = None
#         self.logoBrief = None
#
#     def update_or_create(self):
#         default_dict = {
#             'project_id': self.project_id,
#             'source': self.source,
#             'data': self.data,
#             'update_time': self.update_time,
#
#             'company_name': self.company_name,
#             'pid': self.pid,
#             'name': self.name,
#             'classify': self.classify,
#             'logo': self.logo,
#             'logoBrief': self.logoBrief,
#         }
#         model, create = CompanyAPPModel.objects.update_or_create(
#             project_id=self.project_id,
#             company_name=self.company_name,
#             name=self.name,
#             defaults=default_dict)
#         return create
