# -*- coding: utf-8 -*-
# @File  : serializers.py
# @Date  : 2018/11/15
# @Desc  :

from rest_framework.serializers import Serializer, IntegerField, DictField, CharField


class EdgeSerializer(Serializer):
    source = CharField(max_length=100)
    target = CharField(max_length=100)
    type = CharField(max_length=100)
    data = DictField()


class PortServiceSerializer(Serializer):
    ipaddress = CharField(max_length=100)
    update_time = IntegerField()
    port = IntegerField()
    banner = DictField()
    service = CharField(max_length=100)


class CredentialSerializer(Serializer):
    id = IntegerField()
    username = CharField(max_length=100)
    password = CharField(max_length=100)  # 密码信息和hash信息
    password_type = CharField(max_length=100)
    tag = DictField()  # 标识凭证的标签,如domain名称(mimikatz抓取的)或者url(laNage抓取的)
    source_module = CharField(max_length=255)  # 凭证来源的模块loadpath
    host_ipaddress = CharField(max_length=100)  # 凭证的主机ip地址(注意此信息不与core.host关联)
    desc = CharField(max_length=1000)  # 关于此凭证的说明


class VulnerabilitySerializer(Serializer):
    id = IntegerField()
    ipaddress = CharField(max_length=100)
    source_module_loadpath = CharField(max_length=255)  # 凭证来源的模块loadpath
    update_time = IntegerField()
    extra_data = DictField()
    desc = CharField(max_length=1000)  # 关于此凭证的说明
