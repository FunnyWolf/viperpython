import json

from rest_framework.response import Response

from Lib.api import data_return
from Lib.baseview import BaseView
from Lib.configs import *
from Lib.log import logger
from Lib.webnotice import WebNotice
from WebDatabase.Handle.ipdomain import IPDomain
from WebDatabase.Handle.port import Port
from WebDatabase.Handle.project import Project
from WebDatabase.Handle.webtaskresult import WebTaskResult


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

        project_id = request.query_params.get('project_id', None)

        ipdomain = request.query_params.get('ipdomain', None)
        if ipdomain == '':
            ipdomain = None

        waf_flag = request.query_params.get('waf_flag', None)
        if waf_flag == 'true':
            waf_flag = True
        elif waf_flag == 'false':
            waf_flag = False

        cdn_flag = request.query_params.get('cdn_flag', None)
        if cdn_flag == 'true':
            cdn_flag = True
        elif cdn_flag == 'false':
            cdn_flag = False

        port = request.query_params.get('port', None)
        try:
            port = int(port)
        except Exception as _:
            port = None

        service_s = request.query_params.get('service', None)
        if service_s == '':
            service_s = None

        try:
            result, pagination = IPDomain.list(project_id=project_id, pagination=pagination, ipdomain_s=ipdomain,
                                               port_s=port, waf_flag_s=waf_flag, cdn_flag_s=cdn_flag,
                                               service_s=service_s)
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


class PortView(BaseView):

    def update(self, request, pk=None, **kwargs):
        try:
            ipdomain = request.data.get('ipdomain')
            port = request.data.get('port')
            color = request.data.get('color')
            comment = request.data.get('comment')

            data = Port.update_commnet_by_ipdomain_port(ipdomain=ipdomain, port=port, color=color, comment=comment)
            context = data_return(201, data, Project_MSG_ZH.get(201), Project_MSG_EN.get(201))
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class WebTaskResultView(BaseView):
    def destroy(self, request, *args, **kwargs):
        try:
            context = WebTaskResult.destory()
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class WebNoticesView(BaseView):
    def list(self, request, **kwargs):
        try:
            context = WebNotice.list_notices()
            context = data_return(200, context, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            WebNotice.clean_notices()
            context = data_return(201, {}, Notice_MSG_ZH.get(201), Notice_MSG_EN.get(201))
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)
