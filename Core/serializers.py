# -*- coding: utf-8 -*-
# @File  : serializers.py
# @Date  : 2018/11/15
# @Desc  :

from rest_framework.serializers import ModelSerializer, Serializer

from Core.models import HostModel
from Msgrpc import serializers


class HostSerializer(ModelSerializer):
    class Meta(object):
        model = HostModel
        fields = '__all__'


class UserAPISerializer(Serializer):
    username = serializers.CharField()
    is_superuser = serializers.BooleanField()
