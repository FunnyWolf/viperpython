# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from Lib.api import data_return, get_one_uuid_str
from Lib.configs import DEFAULT_PROJECT_ID, DEFAULT_PROJECT_NAME, DEFAULT_PROJECT_DESC, Project_MSG_ZH, Project_MSG_EN
from Lib.log import logger
from WebDatabase.models import ProjectModel
from WebDatabase.serializers import ProjectSerializer


class Project(object):

    @staticmethod
    def check_default_project():
        if not ProjectModel.objects.filter(project_id=DEFAULT_PROJECT_ID).exists():
            Project.update_or_create(DEFAULT_PROJECT_ID, DEFAULT_PROJECT_NAME, DEFAULT_PROJECT_DESC)

    @staticmethod
    def list_project():
        models = ProjectModel.objects.all()
        result = ProjectSerializer(models, many=True).data
        return result

    @staticmethod
    def update_or_create(project_id=None, name=None, desc=None):
        if project_id is None:
            project_id = get_one_uuid_str()

        default_dict = {
            'project_id': project_id,
            'name': name,
            "desc": desc,
        }

        model, created = ProjectModel.objects.update_or_create(project_id=project_id,
                                                               defaults=default_dict)
        result = ProjectSerializer(model, many=False).data
        return result

    @staticmethod
    def destory(project_id):
        try:
            ProjectModel.objects.filter(project_id=project_id).delete()
            context = data_return(204, {}, Project_MSG_ZH.get(204), Project_MSG_EN.get(204))
        except Exception as E:
            logger.error(E)
            context = data_return(304, {}, Project_MSG_ZH.get(304), Project_MSG_EN.get(304))
        return context
