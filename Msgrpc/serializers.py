# -*- coding: utf-8 -*-
# @File  : serializers.py
# @Date  : 2018/11/15
# @Desc  :

from rest_framework.serializers import *


class SessionLibSerializer(Serializer):
    sessionid = IntegerField()

    # 权限部分
    user = CharField(max_length=100)
    is_system = BooleanField()
    is_admin = BooleanField()
    is_in_admin_group = BooleanField()
    is_in_domain = BooleanField()
    is_uac_enable = BooleanField()
    uac_level = IntegerField()
    integrity = CharField(max_length=100)

    # 进程信息
    pid = IntegerField()
    pname = CharField(max_length=100)
    ppath = CharField(max_length=100)
    puser = CharField(max_length=100)
    parch = CharField(max_length=100)
    processes = ListField()

    load_powershell = BooleanField()
    load_python = BooleanField()

    # 域信息
    domain = CharField(max_length=100)

    # session基本信息
    session_host = CharField(max_length=100)
    type = CharField(max_length=100)
    computer = CharField(max_length=100)
    arch = CharField(max_length=100)
    platform = CharField(max_length=100)
    last_checkin = IntegerField()
    fromnow = IntegerField()

    tunnel_local = CharField(max_length=100)
    tunnel_peer = CharField(max_length=100)
    tunnel_peer_ip = CharField(max_length=100)
    tunnel_peer_locate_zh = CharField(max_length=100)
    tunnel_peer_locate_en = CharField(max_length=100)

    comm_channel_session = IntegerField()
    via_exploit = CharField(max_length=100)
    via_payload = CharField(max_length=100)
    os = CharField(max_length=100)
    os_short = CharField(max_length=100)
    logged_on_users = IntegerField()


class PostModuleSerializer(Serializer):
    NAME_ZH = CharField(max_length=100)
    NAME_EN = CharField(max_length=100)

    DESC_ZH = CharField(max_length=100)
    DESC_EN = CharField(max_length=100)

    REQUIRE_SESSION = BooleanField()
    MODULETYPE = CharField(max_length=100)  # 模块类型
    AUTHOR = ListField()  # 模块作者
    PLATFORM = ListField()  # 平台
    PERMISSIONS = ListField()
    README = ListField()
    ATTCK = ListField()
    REFERENCES = ListField()
    _custom_param = DictField()  # 前端传入的参数信息
    _sessionid = IntegerField()  # 前端传入的sessionid
    _ipaddress = CharField(max_length=100)  # 前端传入的ipaddress信息


class BotModuleSerializer(Serializer):
    NAME_ZH = CharField(max_length=100)
    NAME_EN = CharField(max_length=100)
    DESC_ZH = CharField(max_length=100)
    DESC_EN = CharField(max_length=100)
    MODULETYPE = CharField(max_length=100)  # 模块类型
    AUTHOR = ListField()  # 模块作者
    REFERENCES = ListField()
    README = ListField()
    SEARCH = CharField(max_length=200)
    _custom_param = DictField()  # 前端传入的参数信息
    _ip = CharField(max_length=100)  # 前端传入的ip地址
    _port = IntegerField()  # 前端传入的端口信息
    _protocol = CharField(max_length=100)  # 前端传入的协议类型
