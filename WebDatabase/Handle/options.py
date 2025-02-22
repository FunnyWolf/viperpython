# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from WebDatabase.Handle.component import Component
from WebDatabase.Handle.service import Service


class Options(object):

    @staticmethod
    def list(project_id, table, param):
        options = []
        if table == "ServiceModel" and param == "service":
            options = Service.list_by_project_and_service(project_id=project_id)
        elif table == "ComponentModel" and param == "product_name":
            options = Component.list_by_project_for_component(project_id=project_id)
        return options
