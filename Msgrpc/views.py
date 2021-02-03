# Create your views here.

from rest_framework.generics import UpdateAPIView, DestroyAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from Msgrpc.msgrpc import *
from Msgrpc.serializers import *


class PayloadView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None
    serializer_class = PostModuleSerializer

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
            context = dict_data_return(500, CODE_MSG.get(500), {})
            return Response(context)


class JobView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None  # 设置类的queryset
    serializer_class = PostModuleSerializer  # 设置类的serializer_class

    def destroy(self, request, pk=None, **kwargs):
        try:
            job_id = request.query_params.get('job_id', None)
            if job_id is not None:
                job_id = int(job_id)

            task_uuid = request.query_params.get('uuid', None)
            broker = request.query_params.get('broker', None)
            context = Job.destroy_adv_job(task_uuid=task_uuid, job_id=job_id, broker=broker)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})

        return Response(context)


class HandlerView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None  # 设置类的queryset
    serializer_class = PostModuleSerializer  # 设置类的serializer_class

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
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            jobid = int(request.query_params.get('jobid', None))
            context = Handler.destroy(jobid)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class SessionIOView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None  # 设置类的queryset
    serializer_class = PostModuleSerializer  # 设置类的serializer_class

    def create(self, request, **kwargs):
        try:
            hid = int(request.data.get('hid', None))
            sessionid = int(request.data.get('sessionid', None))
            user_input = str(request.data.get('input', ""))
            context = SessionIO.create(hid, sessionid, user_input)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)

    def update(self, request, pk=None, **kwargs):
        try:
            hid = int(request.data.get('hid', None))
            sessionid = int(request.data.get('sessionid', None))
            context = SessionIO.update(hid, sessionid)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            hid = int(request.query_params.get('hid', None))
            context = SessionIO.destroy(hid)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class SessionView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None  # 设置类的queryset
    serializer_class = SessionLibSerializer  # 设置类的serializer_class

    def list(self, request, **kwargs):
        try:
            sessionid = int(request.query_params.get('sessionid', None))
            context = Session.list(sessionid=sessionid)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)

    def update(self, request, **kwargs):
        try:
            sessionid = int(request.data.get('sessionid', None))
            context = Session.update(sessionid=sessionid)
            return Response(context)
        except Exception as E:
            logger.error(E)

            context = dict_data_return(500, CODE_MSG.get(500), {})
            return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            hid = int(request.query_params.get('sessionid', None))
            context = Session.destroy(hid)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class RouteView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None  # 设置类的queryset
    serializer_class = PostModuleSerializer  # 设置类的serializer_class

    def list(self, request, **kwargs):
        try:
            sessionid = int(request.query_params.get('sessionid', None))
            context = Route.list(sessionid=sessionid)
        except Exception as E:
            logger.exception(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
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
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            subnet = str(request.query_params.get('subnet', None))
            netmask = str(request.query_params.get('netmask', None))
            sessionid = int(request.query_params.get('sessionid', None))
            context = Route.destory(subnet=subnet, netmask=netmask, sessionid=sessionid)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class SocksView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None  # 设置类的queryset
    serializer_class = PostModuleSerializer  # 设置类的serializer_class

    def list(self, request, **kwargs):
        context = Socks.list()
        return Response(context)

    def create(self, request, **kwargs):
        try:
            socks_type = request.data.get('type', None)
            port = int(request.data.get('port', -1))
            context = Socks.create(socks_type=socks_type, port=port)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            socks_type = str(request.query_params.get('type', None))
            jobid = str(request.query_params.get('ID', None))
            context = Socks.destory(socks_type=socks_type, jobid=jobid)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class PortFwdView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None  # 设置类的queryset
    serializer_class = PostModuleSerializer  # 设置类的serializer_class

    def list(self, request, **kwargs):
        try:
            sessionid = int(request.query_params.get('sessionid', None))
            context = PortFwd.list(sessionid=sessionid)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
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
            context = dict_data_return(500, CODE_MSG.get(500), {})
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
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class TransportView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None  # 设置类的queryset
    serializer_class = PostModuleSerializer  # 设置类的serializer_class

    def list(self, request, **kwargs):
        try:
            sessionid = int(request.query_params.get('sessionid', None))
            context = Transport.list(sessionid=sessionid)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)

    def create(self, request, **kwargs):

        try:
            handler = request.data.get('handler', None)
            sessionid = int(request.data.get('sessionid', None))
            context = Transport.create(sessionid=sessionid, handler=handler)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
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
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            context = Transport.destory(query_params=request.query_params)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class HostFileView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    permission_classes = [AllowAny]

    def list(self, request, **kwargs):
        """查询数据库中的信息"""
        try:
            # TODO 下载文件通知
            enfilename = request.query_params.get('en', None)
            filename = FileMsf.decrypt_file_name(enfilename)
            if filename is None:
                context = dict_data_return(500, CODE_MSG.get(500), {})
                return Response(context)
            binary_data = FileMsf.read_msf_file(filename)
            if binary_data is None:
                context = dict_data_return(304, HostFile_MSG.get(304), {})
                return context

            response = HttpResponse(binary_data)
            response['Content-Type'] = 'application/octet-stream'
            response['Content-Disposition'] = f'attachment;filename="{filename}"'
            response['Code'] = 200
            response['Message'] = parse.quote(FileMsf_MSG.get(203))
            remote_client = request.META.get("HTTP_X_REAL_IP")

            Notices.send_info(f"IP: {remote_client} 下载文件 : {filename}")
            return response
        except Exception as E:
            logger.error(E)

            context = dict_data_return(500, CODE_MSG.get(500), {})
            return Response(context)


class FileMsfView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None  # 设置类的queryset
    serializer_class = PostModuleSerializer  # 设置类的serializer_class

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
            context = dict_data_return(500, CODE_MSG.get(500), {})
            return Response(context)

    def create(self, request, **kwargs):
        try:
            file = request.FILES['file']
            context = FileMsf.create(file=file)
            return Response(context)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
            return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            filename = str(request.query_params.get('name', None))
            context = FileMsf.destory(filename)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class FileSessionView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None  # 设置类的queryset
    serializer_class = PostModuleSerializer  # 设置类的serializer_class

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
            context = dict_data_return(500, CODE_MSG.get(500), {})
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
            context = dict_data_return(500, CODE_MSG.get(500), {})
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
            context = dict_data_return(500, CODE_MSG.get(500), {})
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
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class ServiceStatusView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None  # 设置类的queryset
    serializer_class = PostModuleSerializer  # 设置类的serializer_class

    def list(self, request, **kwargs):
        """查询数据库中的信息"""
        context = ServiceStatus.list()
        return Response(context)


class LazyLoaderView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None  # 设置类的queryset
    serializer_class = PostModuleSerializer  # 设置类的serializer_class

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
            context = dict_data_return(500, CODE_MSG.get(500), {})
            return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            loader_uuid = request.query_params.get('uuid', None)
            context = LazyLoader.destory(loader_uuid)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class LazyLoaderInterfaceView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    permission_classes = (AllowAny,)  # 无需认证

    def list(self, request, **kwargs):
        """查询数据库中的信息"""
        req = request.query_params.get('c', None)
        loader_uuid = request.query_params.get('u', None)
        ipaddress = request.META.get("HTTP_X_REAL_IP")
        context = LazyLoader.list_interface(req, loader_uuid, ipaddress)
        return HttpResponse(context)
