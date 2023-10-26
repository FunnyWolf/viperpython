from rest_framework.response import Response

from Lib.api import data_return
from Lib.baseview import BaseView
from Lib.configs import *
from Lib.log import logger
from WebDatabase.Handle.ipdomain import IPDomain
from WebDatabase.Handle.project import Project


# Create your views here.
class ProjectView(BaseView):
    def list(self, request, **kwargs):
        try:
            results = Project.list_project()
            context = data_return(200, results, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        except Exception as E:
            logger.error(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def update(self, request, pk=None, **kwargs):
        try:
            project_id = request.data.get('project_id')
            name = request.data.get('name')
            desc = request.data.get('desc')
            data = Project.update_or_create(project_id, name, desc)
            context = data_return(201, data, Credential_MSG_ZH.get(201), Credential_MSG_EN.get(201))
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def create(self, request, **kwargs):
        try:
            project_id = request.data.get('project_id')
            ipdomain = request.data.get('ipdomain')
            if ipdomain:
                data = IPDomain.update_project_id(project_id, ipdomain)
                context = data_return(201, data, Credential_MSG_ZH.get(201), Credential_MSG_EN.get(201))
            else:
                context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            project_id = request.query_params.get('project_id')
            context = Project.destory(project_id=project_id)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)
