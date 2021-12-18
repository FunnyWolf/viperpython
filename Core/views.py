import datetime

from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.generics import UpdateAPIView, DestroyAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from Core.Handle.currentuser import CurrentUser
from Core.Handle.host import Host
from Core.Handle.hostinfo import HostInfo
from Core.Handle.networksearch import NetworkSearch
from Core.Handle.setting import Settings
from Core.Handle.uuidjson import UUIDJson
from Lib.api import data_return
from Lib.baseview import BaseView
from Lib.configs import *
from Lib.log import logger
from Lib.notice import Notice
from Lib.xcache import Xcache


class NoticesView(BaseView):
    def list(self, request, **kwargs):
        try:
            context = Notice.list_notices()
            context = data_return(200, context, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def create(self, request, pk=None, **kwargs):
        try:
            content = request.data.get('content')
            userkey = request.data.get('userkey', "0")
            context = Notice.send_userinput(content=content, userkey=userkey)
            context = data_return(200, context, Notice_MSG_ZH.get(200), Notice_MSG_EN.get(200))
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            Notice.clean_notices()
            context = data_return(201, {}, Notice_MSG_ZH.get(201), Notice_MSG_EN.get(201))
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class HostView(BaseView):
    def list(self, request, **kwargs):
        context = Host.list()
        return Response(context)

    def update(self, request, pk=None, **kwargs):
        try:
            ipaddress = request.data.get('ipaddress')
            tag = request.data.get('tag')
            comment = request.data.get('comment')
            context = Host.update(ipaddress, tag, comment)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            ipaddress_str = request.data.get('ipaddress')
            # 多个
            if "," in ipaddress_str:
                ipaddress_list = []
                for i in ipaddress_str.split(","):
                    ipaddress_list.append(i)
                context = Host.destory_mulit(ipaddress_list)
            else:
                ipaddress = ipaddress_str
                context = Host.destory_single(ipaddress)
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class HostInfoView(BaseView):
    def list(self, request, **kwargs):
        ipaddress = request.query_params.get('ipaddress')
        host_info = HostInfo.list(ipaddress)
        context = data_return(200, host_info, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        return Response(context)


class UUIDJsonView(BaseView):
    def list(self, request, **kwargs):
        uuid = request.query_params.get('uuid')
        data = UUIDJson.list(uuid)
        context = data_return(200, data, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            context = UUIDJson.destory()
        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class NetworkSearchView(BaseView):
    def list(self, request, **kwargs):
        cmdtype = request.query_params.get('cmdtype')
        if cmdtype is None or cmdtype != "list_config":
            try:
                engine = request.query_params.get('engine')
                inputstr = request.query_params.get('inputstr')
                page = int(request.query_params.get('page', 1))
                size = int(request.query_params.get('size', 100))
                context = NetworkSearch.list_search(engine=engine,
                                                    inputstr=inputstr,
                                                    page=page, size=size)
            except Exception as E:
                logger.error(E)
                context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        else:
            context = NetworkSearch.list_engine()
        return Response(context)


class BaseAuthView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None  # 设置类的queryset
    serializer_class = AuthTokenSerializer  # 设置类的serializer_class
    permission_classes = (AllowAny,)

    def create(self, request, pk=None, **kwargs):

        null_response = {"status": "error", "type": "account", "currentAuthority": "guest",
                         "token": "forguest"}

        # 检查是否为diypassword
        password = request.data.get('password')
        if password == "diypassword":
            context = data_return(302, null_response, BASEAUTH_MSG_ZH.get(302), BASEAUTH_MSG_EN.get(302))
            return Response(context)

        try:
            serializer = AuthTokenSerializer(data=request.data)
            if serializer.is_valid():
                token, created = Token.objects.get_or_create(user=serializer.validated_data['user'])
                time_now = datetime.datetime.now()
                if created or token.created < time_now - datetime.timedelta(minutes=EXPIRE_MINUTES):
                    # 更新创建时间,保持token有效
                    token.delete()
                    token = Token.objects.create(user=serializer.validated_data['user'])
                    token.created = time_now
                    token.save()
                null_response['status'] = 'ok'
                null_response['currentAuthority'] = 'admin'  # 当前为单用户模式,默认为admin
                null_response['token'] = token.key
                # 成功登录通知
                Notice.send_info(f"{serializer.validated_data['user']} 登录成功",
                                 f"{serializer.validated_data['user']} login")
                context = data_return(201, null_response, BASEAUTH_MSG_ZH.get(201), BASEAUTH_MSG_EN.get(201))
                return Response(context)
            else:
                if Xcache.login_fail_count():
                    Notice.send_alert("Viper被暴力破解，服务器地址可能已经暴露",
                                      "Viper has been brute force, and the server address may have been exposed")

                context = data_return(301, null_response, BASEAUTH_MSG_ZH.get(301), BASEAUTH_MSG_EN.get(301))
                return Response(context)
        except Exception as E:
            logger.error(E)
            context = data_return(301, null_response, BASEAUTH_MSG_ZH.get(301), BASEAUTH_MSG_EN.get(301))
            return Response(context)


class CurrentUserView(BaseView):
    def list(self, request, **kwargs):
        """查询数据库中的host信息"""
        user = request.user
        context = CurrentUser.list(user)
        return Response(context)


class SettingView(BaseView):
    def list(self, request, **kwargs):
        kind = request.query_params.get('kind')
        context = Settings.list(kind=kind)
        if isinstance(context, dict):
            return Response(context)
        else:
            return context

    def create(self, request, pk=None, **kwargs):
        """更新host信息到数据库"""
        kind = request.data.get('kind')
        tag = request.data.get('tag')
        setting = request.data.get('setting')
        context = Settings.create(kind=kind, tag=tag, setting=setting)
        return Response(context)
