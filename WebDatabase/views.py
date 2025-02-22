import json

from rest_framework.response import Response

from Lib.api import data_return
from Lib.baseview import BaseView
from Lib.configs import *
from Lib.log import logger
from Lib.webnotice import WebNotice
from WebDatabase.Handle.cluecert import ClueCert
from WebDatabase.Handle.cluecompany import ClueCompany
from WebDatabase.Handle.cluefavicon import ClueFavicon
from WebDatabase.Handle.companyapp import CompanyAPP
from WebDatabase.Handle.companyicp import CompanyICP
from WebDatabase.Handle.companywechat import CompanyWechat
from WebDatabase.Handle.ipdomain import IPDomain
from WebDatabase.Handle.options import Options
from WebDatabase.Handle.port import Port
from WebDatabase.Handle.project import Project
from WebDatabase.Interface.webtaskresult import WebTaskResult


# Create your views here.
class ProjectView(BaseView):
    def list(self, request, **kwargs):
        try:
            results = Project.list_project()
            context = data_return(200, results, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def update(self, request, pk=None, **kwargs):
        try:
            project_id = request.data.get('project_id')
            name = request.data.get('name')
            desc = request.data.get('desc')
            data = Project.update_or_create(project_id=project_id, name=name, desc=desc)
            context = data_return(201, data, Project_MSG_ZH.get(201), Project_MSG_EN.get(201))
        except Exception as E:
            logger.exception(E)
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
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            project_id = request.query_params.get('project_id')
            context = Project.destory(project_id=project_id)
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class IPDomainView(BaseView):
    def list(self, request, **kwargs):

        try:
            pagination = request.query_params.get('pagination')
            pagination = json.loads(pagination)
        except Exception as E:
            logger.exception(E)
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

        alive_flag = request.query_params.get('alive_flag', None)
        if alive_flag == 'true':
            alive_flag = True
        elif alive_flag == 'false':
            alive_flag = False

        port = request.query_params.get('port', None)
        try:
            port = int(port)
        except Exception as _:
            port = None

        services = request.query_params.getlist('service', None)
        components = request.query_params.getlist('component', None)
        try:
            result, pagination = IPDomain.list(project_id=project_id, pagination=pagination, ipdomain_s=ipdomain,
                                               port_s=port, waf_flag_s=waf_flag, cdn_flag_s=cdn_flag, alive_flag=alive_flag,
                                               services_s=services, components_s=components)
            context = data_return(200, {"result": result, "pagination": pagination}, CODE_MSG_ZH.get(200),
                                  CODE_MSG_EN.get(200))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            ipdomain = request.query_params.get('ipdomain')
            context = IPDomain.destory(ipdomain=ipdomain)
        except Exception as E:
            logger.exception(E)
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
            context = data_return(201, data, Port_MSG_ZH.get(201), Port_MSG_EN.get(201))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class OptionsView(BaseView):

    def list(self, request, **kwargs):
        try:
            project_id = request.query_params.get('project_id', None)
            table = request.query_params.get('table', None)
            param = request.query_params.get('param', None)
            options = Options.list(project_id, table, param)
            context = data_return(200, options, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class WebTaskResultView(BaseView):
    def destroy(self, request, *args, **kwargs):
        try:
            context = WebTaskResult.destory()
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class WebNoticesView(BaseView):
    def list(self, request, **kwargs):
        try:
            context = WebNotice.list_notices()
            context = data_return(200, context, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            WebNotice.clean_notices()
            context = data_return(201, {}, Notice_MSG_ZH.get(201), Notice_MSG_EN.get(201))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class CompanyICPView(BaseView):
    def list(self, request, **kwargs):
        try:
            project_id = request.query_params.get('project_id')
            result = CompanyICP.list_by_project(project_id=project_id)
            context = data_return(200, result, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, *args, **kwargs):
        try:
            project_id = request.query_params.get('project_id')
            company_name = request.query_params.get('company_name')
            domain = request.query_params.get('domain')
            context = CompanyICP.destory_by_companyname(company_name=company_name, domain=domain)
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class CompanyAPPView(BaseView):
    def list(self, request, **kwargs):
        try:
            project_id = request.query_params.get('project_id')
            result = CompanyAPP.list_by_project_id(project_id)
            context = data_return(200, result, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, *args, **kwargs):
        try:
            project_id = request.query_params.get('project_id')
            name = request.query_params.get('name')
            company_name = request.query_params.get('company_name')
            context = CompanyAPP.destory_by_company_name_and_name(company_name=company_name, name=name)
            context = data_return(201, context, Notice_MSG_ZH.get(201), Notice_MSG_EN.get(201))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class CompanyMediaView(BaseView):
    def list(self, request, **kwargs):
        try:
            project_id = request.query_params.get('project_id')
            result = CompanyWechat.list_by_project(project_id=project_id)
            context = data_return(200, result, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, *args, **kwargs):
        try:
            project_id = request.query_params.get('project_id')
            wechatId = request.query_params.get('wechatId')
            company_name = request.query_params.get('company_name')
            context = CompanyWechat.destroy(project_id=project_id, wechatId=wechatId)
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class ClueCompanyView(BaseView):
    def list(self, request, **kwargs):
        try:
            project_id = request.query_params.get('project_id')
            result = ClueCompany.list(project_id=project_id)
            context = data_return(200, result, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, *args, **kwargs):
        try:
            company_name = request.query_params.get('company_name')
            context = ClueCompany.destroy_by_company_name(company_name=company_name, refresh=True)
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class ClueFaviconView(BaseView):
    def list(self, request, **kwargs):
        try:
            project_id = request.query_params.get('project_id')
            result = ClueFavicon.list(project_id=project_id)
            context = data_return(200, result, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def create(self, request, **kwargs):
        try:
            ipdomain = request.data.get('ipdomain')
            port = request.data.get('port')
            data = ClueFavicon.update_by_http_favicon(ipdomain=ipdomain, port=port)
            context = data_return(201, data, Clue_MSG_ZH.get(201), Clue_MSG_ZH.get(201))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, *args, **kwargs):
        try:
            id = request.query_params.get('id')
            context = ClueFavicon.destroy_by_id(id=id, refresh=True)
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class ClueCertView(BaseView):
    def list(self, request, **kwargs):
        try:
            project_id = request.query_params.get('project_id')
            result = ClueCert.list(project_id=project_id)
            context = data_return(200, result, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def create(self, request, **kwargs):
        try:
            ipdomain = request.data.get('ipdomain')
            port = request.data.get('port')
            data = ClueCert.update_by_http_Cert(ipdomain=ipdomain, port=port)
            context = data_return(201, data, Clue_MSG_ZH.get(201), Clue_MSG_ZH.get(201))
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, *args, **kwargs):
        try:
            id = request.query_params.get('id')
            context = ClueCert.destroy_by_id(id=id, refresh=True)
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)
