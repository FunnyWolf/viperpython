# -*- coding: utf-8 -*-
# @File  : serializers.py
# @Date  : 2018/11/15
# @Desc  :
from rest_framework.serializers import ModelSerializer

from WebDatabase.models import *


# class ProjectSerializer(ModelSerializer):
#     class Meta(object):
#         model = ProjectModel
#         fields = '__all__'


class ProjectSerializer(ModelSerializer):
    class Meta(object):
        model = ProjectModel
        fields = '__all__'


class IPDomainSerializer(ModelSerializer):
    class Meta(object):
        model = IPDomainModel
        fields = ['project_id', 'ipdomain', 'update_time']


class PortServiceSerializer(ModelSerializer):
    class Meta(object):
        model = PortServiceModel
        fields = ['port', 'response', 'response_hash', 'transport', 'service', 'version', 'update_time']


class LocationSerializer(ModelSerializer):
    class Meta(object):
        model = LocationModel
        fields = ['isp', 'asname', 'geo_info', 'update_time']


class CertSerializer(ModelSerializer):
    class Meta(object):
        model = CertModel
        fields = ['cert', 'jarm', 'subject', 'update_time']


class ScreenshotSerializer(ModelSerializer):
    class Meta(object):
        model = ScreenshotModel
        fields = ['content', 'update_time']


class DNSRecordSerializer(ModelSerializer):
    class Meta(object):
        model = DNSRecordModel
        fields = ['type', 'value', 'update_time']


class DomainICPSerializer(ModelSerializer):
    class Meta(object):
        model = DomainICPModel
        fields = ['ipdomain', 'unit', 'license', 'update_time']


class CDNSerializer(ModelSerializer):
    class Meta(object):
        model = CDNModel
        fields = ['flag', 'update_time']


class HttpBaseSerializer(ModelSerializer):
    class Meta(object):
        model = HttpBaseModel
        fields = ['title', 'status_code', 'header', 'body', 'update_time']


class HttpFaviconSerializer(ModelSerializer):
    class Meta(object):
        model = HttpFaviconModel
        fields = ['hash', 'content', 'update_time']


class ComponentSerializer(ModelSerializer):
    class Meta(object):
        model = ComponentModel
        fields = ['product_name', 'product_version', 'product_type', 'product_catalog', 'product_dict_values',
                  'update_time']


class VulnerabilitySerializer(ModelSerializer):
    class Meta(object):
        model = VulnerabilityModel
        fields = '__all__'
