# -*- coding: utf-8 -*-
# @File  : serializers.py
# @Date  : 2018/11/15
# @Desc  :

# class ProjectSerializer(ModelSerializer):
#     class Meta(object):
#         model = ProjectModel
#         fields = '__all__'


# class ProjectSerializer(ModelSerializer):
#     class Meta(object):
#         model = ProjectModel
#         fields = '__all__'


# class IPDomainSerializer(ModelSerializer):
#     class Meta(object):
#         model = IPDomainModel
#         fields = ['project_id', 'ipdomain', 'company_name', 'update_time', 'source']


# class PortSerializer(ModelSerializer):
#     class Meta(object):
#         model = PortModel
#         fields = ['id', 'port', 'color', 'alive', 'comment', 'update_time', 'source']


# class ServiceSerializer(ModelSerializer):
#     class Meta(object):
#         model = ServiceModel
#         fields = ['response', 'response_hash', 'transport', 'service', 'version', 'update_time', 'source']


# class ServiceWithIPDomainPortSerializer(ModelSerializer):
#     class Meta(object):
#         model = ServiceModel
#         fields = ['ipdomain', "port", 'response', 'response_hash', 'transport', 'service', 'version', 'update_time', 'source']


# class LocationSerializer(ModelSerializer):
#     class Meta(object):
#         model = LocationModel
#         fields = ['isp', 'asname', 'scene_cn', 'scene_en', 'country_cn', 'country_en', 'province_cn', 'province_en', 'city_cn', 'city_en', 'update_time',
#                   'source']


# class CertSerializer(ModelSerializer):
#     class Meta(object):
#         model = CertModel
#         fields = ['cert', 'jarm', 'subject', 'update_time', 'source']


# class ScreenshotSerializer(ModelSerializer):
#     class Meta(object):
#         model = ScreenshotModel
#         fields = ['content', 'update_time', 'source']


# class DNSRecordSerializer(ModelSerializer):
#     class Meta(object):
#         model = DNSRecordModel
#         fields = ['type', 'value', 'update_time', 'source']


# class CDNSerializer(ModelSerializer):
#     class Meta(object):
#         model = CDNModel
#         fields = ['flag', 'domain', 'name', 'link', 'update_time', 'source']

#
# class HttpBaseSerializer(ModelSerializer):
#     class Meta(object):
#         model = HttpBaseModel
#         fields = ['title', 'status_code', 'header', 'body', 'update_time', 'source']


# class HttpFaviconSerializer(ModelSerializer):
#     class Meta(object):
#         model = HttpFaviconModel
#         fields = ['hash', 'content', 'update_time', 'source']


# class WAFSerializer(ModelSerializer):
#     class Meta(object):
#         model = WAFModel
#         fields = ['flag', 'trigger_url', 'name', 'manufacturer', 'update_time', 'source']


# class ComponentSerializer(ModelSerializer):
#     class Meta(object):
#         model = ComponentModel
#         fields = ['product_name', 'product_version', 'product_extrainfo', 'product_type', 'product_catalog',
#                   'update_time', 'source']


# class VulnerabilitySerializer(ModelSerializer):
#     class Meta(object):
#         model = VulnerabilityModel
#         fields = [
#             'id',
#             'name', 'description', 'severity',
#             'template_id', 'matched_at', 'reference', 'request', 'response',
#             'source', 'update_time', 'source'
#         ]


# class CompanyBaseInfoSerializer(ModelSerializer):
#     class Meta(object):
#         model = CompanyBaseInfoModel
#         fields = '__all__'


# class CompanyICPSerializer(ModelSerializer):
#     class Meta(object):
#         model = CompanyICPModel
#         fields = '__all__'


# class CompanyAPPSerializer(ModelSerializer):
#     class Meta(object):
#         model = CompanyAPPModel
#         fields = '__all__'


# class CompanyWechatSerializer(ModelSerializer):
#     class Meta(object):
#         model = CompanyWechatModel
#         fields = '__all__'


# class ClueCompanySerializer(ModelSerializer):
#     class Meta(object):
#         model = ClueCompanyModel
#         fields = '__all__'


# class ClueFaviconSerializer(ModelSerializer):
#     class Meta(object):
#         model = ClueFaviconModel
#         fields = '__all__'


# class ClueCertSerializer(ModelSerializer):
#     class Meta(object):
#         model = ClueCertModel
#         fields = '__all__'

#
# class ClueHttpTitleSerializer(ModelSerializer):
#     class Meta(object):
#         model = ClueHttpTitleModel
#         fields = '__all__'
