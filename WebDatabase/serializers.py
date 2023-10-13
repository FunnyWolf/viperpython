# -*- coding: utf-8 -*-
# @File  : serializers.py
# @Date  : 2018/11/15
# @Desc  :
from rest_framework.serializers import ModelSerializer

from WebDatabase.models import IPDomainModel, PortServiceModel


# from rest_framework.serializers import Serializer, IntegerField, DictField, CharField

class IPDomainSerializer(ModelSerializer):
    class Meta(object):
        model = IPDomainModel
        fields = '__all__'


class PortServiceSerializer(ModelSerializer):
    class Meta(object):
        model = PortServiceModel
        fields = '__all__'
