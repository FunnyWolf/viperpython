from elasticsearch_dsl import Search

from Lib.esclient import EsClient
from WebDatabase.documents import CompanyWechatDocument


class CompanyWechat(object):
    @staticmethod
    def list_by_project(project_id=None):
        response = Search(index=CompanyWechatDocument.Index.name).query('term', project_id=project_id).execute()
        data_dict = EsClient.convert_to_dicts(response)
        return data_dict

    @staticmethod
    def destroy_by_company_name(company_name=None):
        response = Search(index=CompanyWechatDocument.Index.name).query('term', company_name=company_name).delete()
        return response.deleted

#
# class CompanyWechatObject(ProjectBaseObject, WebBaseObject, ConfigBaseObject):
#     def __init__(self):
#         super().__init__()
#         self.company_name = None
#         self.pid = None
#         self.principalName = None
#         self.wechatId = None
#         self.wechatName = None
#         self.wechatIntruduction = None
#         self.wechatLogo = None
#         self.qrcode = None
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
#             'principalName': self.principalName,
#             'wechatId': self.wechatId,
#             'wechatName': self.wechatName,
#             'wechatIntruduction': self.wechatIntruduction,
#             'wechatLogo': self.wechatLogo,
#             'qrcode': self.qrcode,
#
#         }
#         model, create = CompanyWechatModel.objects.update_or_create(
#             project_id=self.project_id,
#             company_name=self.company_name,
#             wechatId=self.wechatId,
#             defaults=default_dict)
#         return create
