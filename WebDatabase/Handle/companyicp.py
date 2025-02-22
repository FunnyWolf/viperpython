from elasticsearch_dsl import Search

from Lib.esclient import EsClient
from WebDatabase.documents import CompanyICPDocument


class CompanyICP(object):
    @staticmethod
    def list_by_project(project_id=None):
        response = Search(index=CompanyICPDocument.Index.name).query('term', project_id=project_id).execute()
        data_dict = EsClient.convert_to_dicts(response)
        return data_dict

    @staticmethod
    def destory_by_companyname(company_name, domain):
        s = CompanyICPDocument.search()
        s = s.filter('term', company_name=company_name)
        s = s.filter('term', domain=domain)
        response = s.delete()

        return response.deleted

# class CompanyICPObject(ProjectBaseObject, WebBaseObject, ConfigBaseObject):
#     def __init__(self):
#         super().__init__()
#         self.company_name = None
#         self.pid = None
#         self.domain = None
#         self.homeSite = None
#         self.icpNo = None
#         self.siteName = None
#
#     def update_or_create(self):
#         default_dict = {
#             'project_id': self.project_id,
#
#             'source': self.source,
#             'data': self.data,
#             'update_time': self.update_time,
#
#             'company_name': self.company_name,
#             'pid': self.pid,
#             'domain': self.domain,
#             'homeSite': self.homeSite,
#             'icpNo': self.icpNo,
#             'siteName': self.siteName,
#         }
#         model, create = CompanyICPModel.objects.update_or_create(
#             project_id=self.project_id,
#             company_name=self.company_name,
#             domain=self.domain,
#             defaults=default_dict)
#         return create
