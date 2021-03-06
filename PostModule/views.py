# Create your views here.
from rest_framework.response import Response

from Lib.api import data_return
from Lib.baseview import BaseView
from Lib.configs import CODE_MSG
from Lib.log import logger
from PostModule.Handle.postmoduleactuator import PostModuleActuator
from PostModule.Handle.postmoduleconfig import PostModuleConfig
from PostModule.Handle.postmoduleresult import PostModuleResult
from PostModule.Handle.postmoduleresulthistory import PostModuleResultHistory


class PostModuleConfigView(BaseView):
    def list(self, request, **kwargs):
        loadpath = request.query_params.get('loadpath', None)

        context = PostModuleConfig.list(loadpath=loadpath)
        return Response(context)

    def update(self, request, **kwargs):
        context = PostModuleConfig.update()
        return Response(context)


class PostModuleActuatorView(BaseView):
    def create(self, request, **kwargs):
        moduletype = request.data.get('moduletype', None)
        if moduletype is None:  # 默认模块
            try:
                sessionid = int(request.data.get('sessionid', None))
                hid = int(request.data.get('hid', None))
                loadpath = str(request.data.get('loadpath', None))
                custom_param = str(request.data.get('custom_param', None))
                context = PostModuleActuator.create_post(loadpath=loadpath,
                                                         sessionid=sessionid,
                                                         hid=hid,
                                                         custom_param=custom_param)
            except Exception as E:
                logger.error(E)
                context = data_return(500, CODE_MSG.get(500), {})
            return Response(context)
        elif moduletype == "Bot":
            try:
                ipportlist = request.data.get('ipportlist', None)
                loadpath = str(request.data.get('loadpath', None))
                custom_param = str(request.data.get('custom_param', None))
                context = PostModuleActuator.create_bot(ipportlist=ipportlist,
                                                        loadpath=loadpath,
                                                        custom_param=custom_param)
            except Exception as E:
                logger.error(E)
                context = data_return(500, CODE_MSG.get(500), {})
            return Response(context)
        else:
            context = data_return(500, CODE_MSG.get(500), {})
            return Response(context)


class PostModuleResultView(BaseView):
    def list(self, request, **kwargs):
        try:
            hid = int(request.query_params.get('hid', None))
            loadpath = str(request.query_params.get('loadpath', None))
            context = PostModuleResult.list(hid=hid, loadpath=loadpath)
        except Exception as E:
            logger.error(E)
            context = data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class PostModuleResultHistoryView(BaseView):
    def destroy(self, request, *args, **kwargs):
        try:

            context = PostModuleResultHistory.destory()
        except Exception as E:
            logger.error(E)
            context = data_return(500, CODE_MSG.get(500), {})
        return Response(context)
