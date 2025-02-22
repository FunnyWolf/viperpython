# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from elasticsearch.exceptions import NotFoundError
from elasticsearch_dsl import Search

from Lib.api import data_return
from Lib.configs import DEFAULT_PROJECT_ID, DEFAULT_PROJECT_NAME, DEFAULT_PROJECT_DESC, Project_MSG_ZH, Project_MSG_EN
from Lib.esclient import EsClient
from Lib.log import logger
from WebDatabase.Handle.cluecompany import ClueCompany
from WebDatabase.Handle.ipdomain import IPDomain
from WebDatabase.documents import ProjectDocument


class Project(object):
    @staticmethod
    def check_default_project():
        doc = ProjectDocument(project_id=DEFAULT_PROJECT_ID, name=DEFAULT_PROJECT_NAME, desc=DEFAULT_PROJECT_DESC)
        try:
            doc_old = doc.get(doc.id)
        except NotFoundError as e:
            doc.save()

    @staticmethod
    def list_project():
        response = Search(index=ProjectDocument.Index.name).execute()
        data_dict = EsClient.convert_to_dicts(response)
        return data_dict

    @staticmethod
    def update_or_create(project_id=None, name=None, desc=None):
        doc = ProjectDocument(project_id=project_id, name=name, desc=desc)
        data = doc.update_or_create(refresh=True)
        return data

    @staticmethod
    def destory(project_id):
        try:
            ClueCompany.delete_by_project_id(project_id)
            IPDomain.delete_by_project(project_id)

            doc = ProjectDocument(project_id=project_id, name=None, desc=None)
            doc.delete(id=doc.id)

            context = data_return(204, {}, Project_MSG_ZH.get(210), Project_MSG_EN.get(210))
        except Exception as E:
            logger.exception(E)
            context = data_return(304, {}, Project_MSG_ZH.get(304), Project_MSG_EN.get(304))
        return context
