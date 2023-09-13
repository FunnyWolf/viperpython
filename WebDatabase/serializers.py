# -*- coding: utf-8 -*-
# @File  : serializers.py
# @Date  : 2018/11/15
# @Desc  :

from rest_framework.serializers import Serializer, IntegerField, DictField, CharField


class IPDomainSerializer(Serializer):
    ipdomain = CharField(max_length=100)
    type = CharField(max_length=100)
    source = CharField(max_length=100)
    data = DictField()
    update_time = IntegerField()


class PortServiceSerializer(Serializer):
    ipdomain = CharField(max_length=100)
    port = IntegerField()
    service = CharField(max_length=100)
    source = CharField(max_length=100)
    data = DictField()
    update_time = IntegerField()


class WebInfomationSerializer(Serializer):
    ipdomain = CharField(max_length=100)
    port = IntegerField()
    title = CharField(max_length=100)
    code = IntegerField()
    html = CharField(max_length=10000)
    source = CharField(max_length=100)
    data = DictField()
    update_time = IntegerField()


class WebFingerprintSerializer(Serializer):
    ipdomain = CharField(max_length=100)
    port = IntegerField()
    plugin = CharField(max_length=100)
    source = CharField(max_length=100)
    data = DictField()
    update_time = IntegerField()


class VulnerabilitySerializer(Serializer):
    ipdomain = CharField(max_length=100)
    port = IntegerField()
    name = CharField(max_length=100)
    desc = CharField(max_length=100)
    source = CharField(max_length=100)
    data = DictField()
    update_time = IntegerField()


class TargetSerializer(Serializer):
    ipdomain = CharField(max_length=100)
    name = CharField(max_length=100)
    desc = CharField(max_length=100)
    source = CharField(max_length=100)
    data = DictField()
    update_time = IntegerField()
