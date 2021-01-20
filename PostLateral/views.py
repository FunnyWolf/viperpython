from rest_framework.generics import UpdateAPIView, DestroyAPIView
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from PostLateral.postlateral import *
from PostLateral.serializers import *


# Create your views here.
class PortServiceView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = PortServiceModel.objects.all()
    serializer_class = PortServiceSerializer

    def list(self, request, **kwargs):
        try:
            hid = int(request.query_params.get('hid', None))
            context = PortService.list(hid=hid)
        except Exception as E:
            logger.error(E)
            context = list_data_return(500, CODE_MSG.get(500), [])
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            hid = int(request.query_params.get('hid', None))
            port = int(request.query_params.get('port', None))
            context = PortService.destory(hid=hid, port=port)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class CredentialView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = CredentialModel.objects.all()  # 设置类的queryset
    serializer_class = CredentialSerializer  # 设置类的serializer_class

    def list(self, request, **kwargs):
        try:
            context = Credential.list()
        except Exception as E:
            logger.error(E)
            context = list_data_return(500, CODE_MSG.get(500), [])
        return Response(context)

    def create(self, request, **kwargs):
        try:
            username = str(request.data.get('username', ""))
            password = str(request.data.get('password', ""))
            windows_domain = request.data.get('windows-domain', None)
            windows_type = request.data.get('windows-type', None)
            if windows_domain and windows_type:
                # windows类型凭证
                tag = {'domain': windows_domain, 'type': windows_type}
                password_type = "windows"
            else:
                tag = {}
                password_type = "userinput"

            source_module = "用户手工输入"
            context = Credential.create(username, password, password_type, source_module, tag)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)

    def update(self, request, pk=None, **kwargs):

        try:
            cid = int(request.data.get('id', None))
            desc = request.data.get('desc', None)
            context = Credential.update(cid, desc)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            cid = int(request.query_params.get('id', None))
            context = Credential.destory(cid=cid)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class VulnerabilityView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = VulnerabilityModel.objects.all()  # 设置类的queryset
    serializer_class = VulnerabilitySerializer  # 设置类的serializer_class

    def list(self, request, **kwargs):
        try:
            hid = int(request.query_params.get('hid', -1))
            context = Vulnerability.list(hid=hid)
        except Exception as E:
            logger.error(E)
            context = list_data_return(500, CODE_MSG.get(500), [])
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            vid = int(request.query_params.get('id', None))
            context = Vulnerability.destory(vid=vid)
        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
        return Response(context)
