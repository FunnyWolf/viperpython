# -*- coding: utf-8 -*-
# @File  : serializers.py
# @Date  : 2018/11/15
# @Desc  :
from rest_framework.serializers import ModelSerializer

from WebDatabase.models import *


# from rest_framework.serializers import Serializer, IntegerField, DictField, CharField
class ProjectSerializer(ModelSerializer):
    class Meta(object):
        model = ProjectModel
        fields = '__all__'


class IPDomainSerializer(ModelSerializer):
    class Meta(object):
        model = IPDomainModel
        fields = '__all__'


class PortServiceSerializer(ModelSerializer):
    class Meta(object):
        model = PortServiceModel
        fields = '__all__'


class LocationSerializer(ModelSerializer):
    class Meta(object):
        model = LocationModel
        fields = '__all__'


class CertSerializer(ModelSerializer):
    class Meta(object):
        model = CertModel
        fields = '__all__'


class DNSRecordSerializer(ModelSerializer):
    class Meta(object):
        model = DNSRecordModel
        fields = '__all__'


class DomainICPSerializer(ModelSerializer):
    class Meta(object):
        model = DomainICPModel
        fields = '__all__'


class HttpBaseSerializer(ModelSerializer):
    class Meta(object):
        model = HttpBaseModel
        fields = '__all__'


class HttpFaviconSerializer(ModelSerializer):
    class Meta(object):
        model = HttpFaviconModel
        fields = '__all__'


class ComponentSerializer(ModelSerializer):
    class Meta(object):
        model = ComponentModel
        fields = '__all__'


class VulnerabilitySerializer(ModelSerializer):
    class Meta(object):
        model = VulnerabilityModel
        fields = '__all__'
