# Create your views here.
from rest_framework.response import Response

from Lib.api import data_return
from Lib.baseview import BaseView
from Lib.configs import CODE_MSG_ZH, CODE_MSG_EN
from Lib.log import logger
from PostModule.Handle.postmoduleactuator import PostModuleActuator
from PostModule.Handle.postmoduleauto import PostModuleAuto
from PostModule.Handle.postmoduleconfig import PostModuleConfig
from PostModule.Handle.postmoduleresult import PostModuleResult
from PostModule.Handle.postmoduleresulthistory import PostModuleResultHistory
from PostModule.Handle.postmodulescheduler import PostModuleScheduler
from PostModule.Handle.proxyhttpscan import ProxyHttpScan


class PostModuleConfigView(BaseView):
    def list(self, request, **kwargs):
        loadpath = request.query_params.get('loadpath')

        context = PostModuleConfig.list(loadpath=loadpath)
        return Response(context)

    def update(self, request, **kwargs):
        context = PostModuleConfig.update()
        return Response(context)


class PostModuleActuatorView(BaseView):
    def create(self, request, **kwargs):
        moduletype = request.data.get('moduletype')
        if moduletype is None:  # 默认模块
            try:
                sessionid = int(request.data.get('sessionid'))
                ipaddress = request.data.get('ipaddress')
                loadpath = request.data.get('loadpath')
                custom_param = request.data.get('custom_param')
                context = PostModuleActuator.create_post(loadpath=loadpath,
                                                         sessionid=sessionid,
                                                         ipaddress=ipaddress,
                                                         custom_param=custom_param)
            except Exception as E:
                logger.error(E)
                context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
            return Response(context)
        elif moduletype == "Bot":
            try:
                ipportlist = request.data.get('ipportlist')
                loadpath = request.data.get('loadpath')
                custom_param = request.data.get('custom_param')
                context = PostModuleActuator.create_bot(ipportlist=ipportlist,
                                                        loadpath=loadpath,
                                                        custom_param=custom_param)
            except Exception as E:
                logger.error(E)
                context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
            return Response(context)
        else:
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
            return Response(context)


class PostModuleResultView(BaseView):
    def list(self, request, **kwargs):
        try:
            ipaddress = request.query_params.get('ipaddress')
            loadpath = request.query_params.get('loadpath')
            context = PostModuleResult.list(ipaddress=ipaddress, loadpath=loadpath)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class PostModuleResultHistoryView(BaseView):
    def destroy(self, request, *args, **kwargs):
        try:

            context = PostModuleResultHistory.destory()
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class PostModuleAutoView(BaseView):
    def list(self, request, **kwargs):
        try:
            context = PostModuleAuto.list()
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def create(self, request, **kwargs):
        try:
            module_type = request.data.get('module_type')
            loadpath = request.data.get('loadpath')
            custom_param = request.data.get('custom_param')
            scheduler_session = request.data.get('scheduler_session')
            scheduler_interval = request.data.get('scheduler_interval')

            if module_type == "auto":
                context = PostModuleAuto.create(loadpath=loadpath,
                                                custom_param=custom_param)
            elif module_type == "scheduler":
                context = PostModuleScheduler.create(loadpath=loadpath,
                                                     custom_param=custom_param,
                                                     scheduler_session=scheduler_session,
                                                     scheduler_interval=scheduler_interval)
            else:
                context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def update(self, request, pk=None, **kwargs):
        try:
            module_type = request.data.get('module_type')
            job_id = request.data.get('job_id')
            action = request.data.get('action')
            context = PostModuleScheduler.update(job_id=job_id, action=action)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            module_type = request.query_params.get('module_type')
            if module_type == "auto":
                module_uuid = request.query_params.get('_module_uuid')
                context = PostModuleAuto.destory(module_uuid=module_uuid)
            elif module_type == "scheduler":
                job_id = request.query_params.get('job_id')
                context = PostModuleScheduler.destory(job_id)
            else:
                context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class ProxyHttpScanView(BaseView):
    def list(self, request, **kwargs):
        try:
            context = ProxyHttpScan.list()
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def create(self, request, **kwargs):
        try:
            loadpath = request.data.get('loadpath')
            custom_param = request.data.get('custom_param')
            context = ProxyHttpScan.create(loadpath=loadpath,
                                           custom_param=custom_param)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            module_uuid = request.query_params.get('_module_uuid')
            context = ProxyHttpScan.destory(module_uuid=module_uuid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)
