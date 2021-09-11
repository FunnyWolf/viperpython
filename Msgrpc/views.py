# Create your views here.

import json
from urllib.parse import quote

from django.shortcuts import HttpResponse
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from Lib.api import data_return
from Lib.baseview import BaseView
from Lib.configs import *
from Lib.log import logger
from Lib.notice import Notice
from Msgrpc.Handle.filemsf import FileMsf
from Msgrpc.Handle.filesession import FileSession
from Msgrpc.Handle.handler import Handler
from Msgrpc.Handle.job import Job
from Msgrpc.Handle.lazyloader import LazyLoader
from Msgrpc.Handle.payload import Payload
from Msgrpc.Handle.portfwd import PortFwd
from Msgrpc.Handle.route import Route
from Msgrpc.Handle.servicestatus import ServiceStatus
from Msgrpc.Handle.session import Session
from Msgrpc.Handle.sessionio import SessionIO
from Msgrpc.Handle.socks import Socks
from Msgrpc.Handle.transport import Transport
from Msgrpc.Handle.webdelivery import WebDelivery


class PayloadView(BaseView):
    def create(self, request, **kwargs):
        try:
            mname = str(request.data.get('mname', None))
            opts = request.data.get('opts', None)
            if isinstance(opts, str):
                opts = json.loads(opts)

            response = Payload.create(mname, opts)

            if isinstance(response, dict):
                return Response(response)
            else:
                return response

        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
            return Response(context)


class JobView(BaseView):
    def destroy(self, request, pk=None, **kwargs):
        try:
            try:
                job_id = int(request.query_params.get('job_id', None))
            except Exception as _:
                job_id = None
            task_uuid = request.query_params.get('uuid', None)
            broker = request.query_params.get('broker', None)
            context = Job.destroy_adv_job(task_uuid=task_uuid, job_id=job_id, broker=broker)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))

        return Response(context)


class HandlerView(BaseView):
    def list(self, request, **kwargs):
        data = Handler.list()
        return Response(data)

    def create(self, request, **kwargs):
        try:
            opts = request.data.get('opts', None)
            if isinstance(opts, str):
                opts = json.loads(opts)
            context = Handler.create(opts)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            jobid = int(request.query_params.get('jobid', None))
            context = Handler.destroy(jobid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class WebDeliveryView(BaseView):
    def list(self, request, **kwargs):
        data = WebDelivery.list()
        return Response(data)

    def create(self, request, **kwargs):
        try:
            data = request.data
            handlerconf = json.loads(data.get('handlerconf', None))
            handlerconf.pop("TARGET")
            data.update(handlerconf)
            data.pop('handlerconf')
            data["disablepayloadhandler"] = True
            context = WebDelivery.create(data)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            jobid = int(request.query_params.get('jobid', None))
            context = WebDelivery.destroy(jobid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class SessionIOView(BaseView):
    def create(self, request, **kwargs):
        try:
            ipaddress = request.data.get('ipaddress', None)
            sessionid = int(request.data.get('sessionid', None))
            user_input = str(request.data.get('input', ""))
            context = SessionIO.create(ipaddress, sessionid, user_input)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def update(self, request, pk=None, **kwargs):
        try:
            ipaddress = request.data.get('ipaddress', None)
            sessionid = int(request.data.get('sessionid', None))
            context = SessionIO.update(ipaddress, sessionid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            ipaddress = request.query_params.get('ipaddress', None)
            context = SessionIO.destroy(ipaddress)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class SessionView(BaseView):
    def list(self, request, **kwargs):
        try:
            sessionid = int(request.query_params.get('sessionid', None))
            context = Session.list(sessionid=sessionid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def update(self, request, **kwargs):
        try:
            sessionid = int(request.data.get('sessionid', None))
            context = Session.update(sessionid=sessionid)
            return Response(context)
        except Exception as E:
            logger.error(E)

            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
            return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            sessionid = int(request.query_params.get('sessionid', None))
            context = Session.destroy(sessionid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class RouteView(BaseView):
    def list(self, request, **kwargs):
        try:
            sessionid = int(request.query_params.get('sessionid', None))
            context = Route.list(sessionid=sessionid)
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def create(self, request, **kwargs):
        try:
            subnet = request.data.get('subnet', None)
            netmask = request.data.get('netmask', None)
            sessionid = int(request.data.get('sessionid', None))
            autoroute = request.data.get('autoroute', False)
            context = Route.create(subnet=subnet, netmask=netmask, sessionid=sessionid, autoroute=autoroute)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            subnet = str(request.query_params.get('subnet', None))
            netmask = str(request.query_params.get('netmask', None))
            sessionid = int(request.query_params.get('sessionid', None))
            context = Route.destory(subnet=subnet, netmask=netmask, sessionid=sessionid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class SocksView(BaseView):

    def create(self, request, **kwargs):
        try:
            socks_type = request.data.get('type', None)
            port = int(request.data.get('port', -1))
            context = Socks.create(socks_type=socks_type, port=port)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            socks_type = str(request.query_params.get('type', None))
            jobid = str(request.query_params.get('ID', None))
            context = Socks.destory(socks_type=socks_type, jobid=jobid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class PortFwdView(BaseView):
    def list(self, request, **kwargs):
        try:
            sessionid = int(request.query_params.get('sessionid', None))
            context = PortFwd.list(sessionid=sessionid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def create(self, request, **kwargs):
        try:
            lport = int(request.data.get('lport', None))
        except Exception as _:
            lport = None
        try:
            rport = int(request.data.get('rport', None))
        except Exception as _:
            rport = None
        try:
            sessionid = int(request.data.get('sessionid', None))
        except Exception as _:
            sessionid = None

        try:
            portfwdtype = request.data.get('type', None)
            lhost = request.data.get('lhost', None)
            rhost = request.data.get('rhost', None)
            context = PortFwd.create(portfwdtype=portfwdtype,
                                     lhost=lhost, lport=lport, rhost=rhost, rport=rport,
                                     sessionid=sessionid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            rport = int(request.query_params.get('rport', None))
        except Exception as _:
            rport = None
        try:
            lport = int(request.query_params.get('lport', None))
        except Exception as _:
            lport = None
        try:
            sessionid = int(request.query_params.get('sessionid', None))
        except Exception as _:
            sessionid = None
        try:
            lhost = request.query_params.get('lhost', None)
            rhost = request.query_params.get('rhost', None)
            portfwdtype = str(request.query_params.get('type', None))
            context = PortFwd.destory(portfwdtype=portfwdtype,
                                      rport=rport, lport=lport,
                                      lhost=lhost, rhost=rhost,
                                      sessionid=sessionid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class TransportView(BaseView):
    def list(self, request, **kwargs):
        try:
            sessionid = int(request.query_params.get('sessionid', None))
            context = Transport.list(sessionid=sessionid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def create(self, request, **kwargs):

        try:
            handler = request.data.get('handler', None)
            sessionid = int(request.data.get('sessionid', None))
            context = Transport.create(sessionid=sessionid, handler=handler)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def update(self, request, pk=None, **kwargs):
        """更新后台host信息到数据库"""
        try:
            action = request.data.get('action', None)
            sleep = int(request.data.get('sleep', 0))
            sessionid = int(request.data.get('sessionid', None))
            context = Transport.update(sessionid=sessionid, action=action, sleep=sleep)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            context = Transport.destory(query_params=request.query_params)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class HostFileView(BaseView):
    permission_classes = [AllowAny]

    def list(self, request, **kwargs):
        """查询数据库中的信息"""
        try:
            enfilename = request.query_params.get('en', None)
            filename = FileMsf.decrypt_file_name(enfilename)
            if filename is None:
                context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
                return Response(context)
            binary_data = FileMsf.read_msf_file(filename)
            if binary_data is None:
                context = data_return(304, {}, HostFile_MSG_ZH.get(304), HostFile_MSG_EN.get(304))
                return context

            response = HttpResponse(binary_data)
            response['Content-Type'] = 'application/octet-stream'
            response['Content-Disposition'] = f'attachment;filename="{filename}"'
            response['Code'] = 200
            response['Msg_zh'] = quote(FileMsf_MSG_ZH.get(203))
            response['Msg_en'] = quote(FileMsf_MSG_EN.get(203))
            remote_client = request.META.get("HTTP_X_REAL_IP")

            Notice.send_info(f"IP: {remote_client} 下载文件: {filename}", f"IP: {remote_client} Download: {filename}")
            return response
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
            return Response(context)


class FileMsfView(BaseView):
    def list(self, request, **kwargs):
        """查询数据库中的信息"""
        try:
            filename = request.query_params.get('name', None)
            action = request.query_params.get('action', None)
            context = FileMsf.list(filename, action)
            if isinstance(context, dict):
                return Response(context)
            else:
                return context
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
            return Response(context)

    def create(self, request, **kwargs):
        try:
            file = request.FILES['file']
            context = FileMsf.create(file=file)
            return Response(context)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
            return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            filename = str(request.query_params.get('name', None))
            context = FileMsf.destory(filename)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class FileSessionView(BaseView):
    def list(self, request, **kwargs):
        """查询数据库中的信息"""
        try:
            operation = request.query_params.get('operation', None)
            sessionid = int(request.query_params.get('sessionid', None))
            filepath = request.query_params.get('filepath', None)
            dirpath = request.query_params.get('dirpath', None)
            arg = request.query_params.get('arg', None)
            context = FileSession.list(sessionid=sessionid, filepath=filepath, dirpath=dirpath, operation=operation,
                                       arg=arg)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def create(self, request, **kwargs):
        try:
            operation = request.data.get('operation', None)
            sessionid = int(request.data.get('sessionid', None))
            dirpath = request.data.get('dirpath', None)
            filename = request.data.get('filename', None)
            context = FileSession.create(sessionid=sessionid, filename=filename, dirpath=dirpath, operation=operation)
            return Response(context)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
            return Response(context)

    def update(self, request, pk=None, **kwargs):
        try:
            sessionid = int(request.data.get('sessionid', None))
            filepath = request.data.get('filepath', None)
            filedata = request.data.get('filedata', None)
            context = FileSession.update(sessionid=sessionid, filepath=filepath, filedata=filedata)
            return Response(context)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
            return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            operation = request.query_params.get('operation', None)
            sessionid = int(request.query_params.get('sessionid', None))
            filepath = request.query_params.get('filepath', None)
            dirpath = request.query_params.get('dirpath', None)
            context = FileSession.destory(sessionid=sessionid, filepath=filepath, dirpath=dirpath, operation=operation)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class ServiceStatusView(BaseView):
    def list(self, request, **kwargs):
        """查询msfrpc服务状态"""
        context = ServiceStatus.list()
        return Response(context)


class LazyLoaderView(BaseView):
    def list(self, request, **kwargs):
        """查询数据库中的信息"""

        sourcecode = request.query_params.get('sourcecode', None)
        if sourcecode is not None:
            response = LazyLoader.source_code()
            return response
        else:
            context = LazyLoader.list()
            return Response(context)

    def update(self, request, pk=None, **kwargs):
        try:
            loader_uuid = request.data.get('uuid', None)
            field = request.data.get('field', None)
            data = request.data.get('data', None)
            context = LazyLoader.update(loader_uuid, field, data)
            return Response(context)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
            return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            loader_uuid = request.query_params.get('uuid', None)
            context = LazyLoader.destory(loader_uuid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class LazyLoaderInterfaceView(BaseView):
    permission_classes = (AllowAny,)  # 无需认证

    def list(self, request, **kwargs):
        """查询数据库中的信息"""
        req = request.query_params.get('c', None)
        loader_uuid = request.query_params.get('u', None)
        ipaddress = request.META.get("HTTP_X_REAL_IP")
        context = LazyLoader.list_interface(req, loader_uuid, ipaddress)
        return HttpResponse(context)
