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


class PortSerializer(ModelSerializer):
    class Meta(object):
        model = PortModel
        fields = ['id', 'port', 'color', 'comment', 'update_time']


class ServiceSerializer(ModelSerializer):
    class Meta(object):
        model = ServiceModel
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
        fields = ['flag', 'domain', 'name', 'link', 'update_time']


class HttpBaseSerializer(ModelSerializer):
    class Meta(object):
        model = HttpBaseModel
        fields = ['title', 'status_code', 'header', 'body', 'update_time']


class HttpFaviconSerializer(ModelSerializer):
    class Meta(object):
        model = HttpFaviconModel
        fields = ['hash', 'content', 'update_time']


class WAFSerializer(ModelSerializer):
    class Meta(object):
        model = WAFModel
        fields = ['flag', 'trigger_url', 'name', 'manufacturer', 'update_time']


class ComponentSerializer(ModelSerializer):
    class Meta(object):
        model = ComponentModel
        fields = ['product_name', 'product_version', 'product_type', 'product_catalog', 'product_dict_values',
                  'update_time']


class VulnerabilitySerializer(ModelSerializer):
    class Meta(object):
        model = VulnerabilityModel
        fields = ['id', 'name', 'description', 'severity', 'key', 'tool', 'source', 'update_time']


class CompanyBaseInfoSerializer(ModelSerializer):
    class Meta(object):
        model = CompanyBaseInfoModel
        fields = '__all__'


class CompanyICPSerializer(ModelSerializer):
    class Meta(object):
        model = CompanyICPModel
        fields = '__all__'


class CompanyAPPSerializer(ModelSerializer):
    class Meta(object):
        model = CompanyAPPModel
        fields = '__all__'


class CompanyWechatSerializer(ModelSerializer):
    class Meta(object):
        model = CompanyWechatModel
        fields = '__all__'