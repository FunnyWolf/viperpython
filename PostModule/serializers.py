# -*- coding: utf-8 -*-
# @File  : serializers.py
# @Date  : 2018/11/15
# @Desc  :

from rest_framework.serializers import Serializer, IntegerField, CharField, DictField


class PostModuleResultHistorySerializer(Serializer):
    hid = IntegerField()
    loadpath = CharField(max_length=300)
    update_time = IntegerField()
    opts = DictField()
    result = CharField(max_length=800)
