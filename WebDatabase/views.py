import json

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
            context = data_return(201, data, Project_MSG_ZH.get(201), Project_MSG_EN.get(201))
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
                context = data_return(201, data, Project_MSG_ZH.get(202), Project_MSG_ZH.get(202))
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


class IPDomainView(BaseView):
    def list(self, request, **kwargs):

        try:
            pagination = request.query_params.get('pagination')
            pagination = json.loads(pagination)
        except Exception as E:
            logger.error(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
            return Response(context)

        try:
            project_id = request.query_params.get('project_id', None)
            result, pagination = IPDomain.list(project_id=project_id, pagination=pagination)
            context = data_return(200, {"result": result, "pagination": pagination}, CODE_MSG_ZH.get(200),
                                  CODE_MSG_EN.get(200))
        except Exception as E:
            logger.error(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            ipdomain = request.query_params.get('ipdomain')
            context = IPDomain.destory(ipdomain=ipdomain)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)
