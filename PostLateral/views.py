from rest_framework.response import Response

from Lib.api import data_return
from Lib.baseview import BaseView
from Lib.configs import *
from Lib.log import logger
from PostLateral.Handle.credential import Credential
from PostLateral.Handle.portservice import PortService
from PostLateral.Handle.vulnerability import Vulnerability


# Create your views here.
class PortServiceView(BaseView):
    def list(self, request, **kwargs):
        try:
            ipaddress = request.query_params.get('ipaddress')
            context = PortService.list(ipaddress=ipaddress)
        except Exception as E:
            logger.error(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            ipaddress = request.query_params.get('ipaddress')
            port = int(request.query_params.get('port'))
            context = PortService.destory(ipaddress=ipaddress, port=port)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class CredentialView(BaseView):
    def list(self, request, **kwargs):
        try:
            context = Credential.list()
        except Exception as E:
            logger.error(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def create(self, request, **kwargs):
        try:
            username = request.data.get('username')
            password = request.data.get('password')
            windows_domain = request.data.get('windows-domain')
            windows_type = request.data.get('windows-type')
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
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def update(self, request, pk=None, **kwargs):

        try:
            cid = int(request.data.get('id'))
            desc = request.data.get('desc')
            context = Credential.update(cid, desc)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            cid = int(request.query_params.get('id'))
            context = Credential.destory(cid=cid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class VulnerabilityView(BaseView):
    def list(self, request, **kwargs):
        try:
            ipaddress = request.query_params.get('ipaddress')
            context = Vulnerability.list(ipaddress=ipaddress)
        except Exception as E:
            logger.error(E)
            context = data_return(500, [], CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            vid = int(request.query_params.get('id'))
            context = Vulnerability.destory(vid=vid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)
