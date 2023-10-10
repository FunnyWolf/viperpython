# -*- coding: utf-8 -*-
# @File  : serializers.py
# @Date  : 2018/11/15
# @Desc  :
from rest_framework.serializers import ModelSerializer

from WebDatabase.models import IPDomainModel


# from rest_framework.serializers import Serializer, IntegerField, DictField, CharField

class IPDomainSerializer(ModelSerializer):
    class Meta(object):
        model = IPDomainModel
        fields = '__all__'
