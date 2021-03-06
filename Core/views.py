import datetime

from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.generics import UpdateAPIView, DestroyAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from Core.Handle.currentuser import CurrentUser
from Core.Handle.host import Host
from Core.Handle.networksearch import NetworkSearch
from Core.Handle.networktopology import NetworkTopology
from Core.Handle.setting import Settings
from Lib.api import data_return
from Lib.baseview import BaseView
from Lib.configs import *
from Lib.log import logger
from Lib.notice import Notice


class NoticesView(BaseView):
    def list(self, request, **kwargs):
        try:
            context = Notice.list_notices()
            context = data_return(200, CODE_MSG.get(200), context)
        except Exception as E:
            logger.error(E)
            context = data_return(500, CODE_MSG.get(500), {})
        return Response(context)

    def create(self, request, pk=None, **kwargs):
        try:
            content = str(request.data.get('content', None))
            userkey = str(request.data.get('userkey', "0"))
            context = Notice.send_userinput(content=content, userkey=userkey)
            context = data_return(200, Notice_MSG.get(200), context)
        except Exception as E:
            logger.error(E)
            context = data_return(500, CODE_MSG.get(500), {})
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            Notice.clean_notices()
            context = data_return(201, Notice_MSG.get(201), {})
        except Exception as E:
            logger.error(E)
            context = data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class HostView(BaseView):
    def list(self, request, **kwargs):
        context = Host.list()
        return Response(context)

    def update(self, request, pk=None, **kwargs):
        try:
            hid = int(request.data.get('hid', None))
            tag = str(request.data.get('tag', None))
            comment = request.data.get('comment', None)
            context = Host.update(hid, tag, comment)
        except Exception as E:
            logger.error(E)
            context = data_return(500, CODE_MSG.get(500), {})
        return Response(context)

    def destroy(self, request, pk=None, **kwargs):
        try:
            hid_str = request.query_params.get('hid', -1)
            # 多个
            if "," in hid_str:
                hids = []
                for i in hid_str.split(","):
                    hids.append(int(i))
                context = Host.destory_mulit(hids)
            else:
                hid = int(hid_str)
                context = Host.destory_single(hid)
        except Exception as E:
            logger.error(E)
            context = data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class NetworkSearchView(BaseView):
    def list(self, request, **kwargs):
        try:
            engine = str(request.query_params.get('engine', None))
            querystr = str(request.query_params.get('querystr', None))
            page = int(request.query_params.get('page', 1))
            size = int(request.query_params.get('size', 100))
            context = NetworkSearch.list(engine=engine, querystr=querystr, page=page, size=size)
        except Exception as E:
            logger.error(E)
            context = data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class NetworkTopologyView(BaseView):
    def list(self, request, **kwargs):
        context = NetworkTopology.load_cache()
        return Response(context)

    def update(self, request, pk=None, **kwargs):
        try:
            data = request.data.get('data', None)
            context = NetworkTopology.set_cache(data)
            return Response(context)
        except Exception as E:
            logger.error(E)

            context = data_return(500, CODE_MSG.get(500), {})
        return Response(context)


class BaseAuthView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = None  # 设置类的queryset
    serializer_class = AuthTokenSerializer  # 设置类的serializer_class
    permission_classes = (AllowAny,)

    def create(self, request, pk=None, **kwargs):

        null_response = {"status": "error", "type": "account", "currentAuthority": "guest",
                         "token": "forguest"}

        # 检查是否为diypassword
        password = request.data.get('password', None)
        if password == "diypassword":
            context = data_return(302, BASEAUTH_MSG.get(302), null_response)
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
                Notice.send_info(f"{serializer.validated_data['user']} 成功登录")
                context = data_return(201, BASEAUTH_MSG.get(201), null_response)
                return Response(context)
            context = data_return(301, BASEAUTH_MSG.get(301), null_response)
            return Response(context)
        except Exception as E:
            logger.error(E)
            context = data_return(301, BASEAUTH_MSG.get(301), null_response)
            return Response(context)


class CurrentUserView(BaseView):
    def list(self, request, **kwargs):
        """查询数据库中的host信息"""
        user = request.user
        context = CurrentUser.list(user)
        return Response(context)


class SettingView(BaseView):
    def list(self, request, **kwargs):
        kind = str(request.query_params.get('kind', None))
        context = Settings.list(kind=kind)
        return Response(context)

    def create(self, request, pk=None, **kwargs):
        """更新host信息到数据库"""
        kind = str(request.data.get('kind', None))
        tag = str(request.data.get('tag', None))
        setting = request.data.get('setting', None)
        context = Settings.create(kind=kind, tag=tag, setting=setting)
        return Response(context)
