# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from elasticsearch_dsl import Search

from Lib.esclient import EsClient
from WebDatabase.documents import ClueCompanyDocument, CompanyAPPDocument, CompanyICPDocument, CompanyWechatDocument


class ClueCompany(object):

    @staticmethod
    def list(project_id=None):
        response = Search(index=ClueCompanyDocument.Index.name).query('term', project_id=project_id).execute()
        data_dict = EsClient.convert_to_dicts(response)
        return data_dict

    @staticmethod
    def delete_by_project_id(project_id=None):
        response = Search(index=ClueCompanyDocument.Index.name).query('term', project_id=project_id).delete()
        return response.deleted

    @staticmethod
    def destroy_by_company_name(company_name=None, refresh=False):
        response = Search(index=CompanyAPPDocument.Index.name).query('term', company_name=company_name).delete()
        response = Search(index=CompanyICPDocument.Index.name).query('term', company_name=company_name).delete()
        response = Search(index=CompanyWechatDocument.Index.name).query('term', company_name=company_name).delete()
        response = Search(index=ClueCompanyDocument.Index.name).query('term', company_name=company_name).delete()
        if refresh:
            raw_es_client = EsClient.raw_es_client()
            raw_es_client.indices.refresh(index=ClueCompanyDocument.Index.name)
        return response.deleted
