# -*- coding: utf-8 -*-
# @File  : serializers.py
# @Date  : 2018/11/15
# @Desc  :

from rest_framework.serializers import ModelSerializer

from Core.models import HostModel


class HostSerializer(ModelSerializer):
    class Meta(object):
        model = HostModel
        fields = '__all__'
