from django.db import models

from Core.models import DiyDictField, DiyListField


# Create your models here.
class WebBaseModel(models.Model):
    source = models.CharField(blank=True, null=True, max_length=100)  # 信息来源
    source_key = models.CharField(blank=True, null=True, max_length=100)  # 信息来源
    data = DiyDictField(default={})
    update_time = models.IntegerField(default=0)

    class Meta:
        abstract = True


class DNSRecordModel(WebBaseModel):
    ip = models.CharField(blank=True, null=True, max_length=100)
    domain = models.CharField(blank=True, null=True, max_length=100)
    type = models.CharField(blank=True, null=True, max_length=100)
    value = models.CharField(blank=True, null=True, max_length=100)


class IPDomainBaseModel(WebBaseModel):
    ipdomain = models.CharField(blank=True, null=True, max_length=100)

    class Meta:
        abstract = True


# 存储目标相关信息
class TargetModel(IPDomainBaseModel):
    name = models.TextField(blank=True, null=True)
    desc = models.TextField(blank=True, null=True)


class IPDomainModel(IPDomainBaseModel):
    TYPE = (
        ('ipaddress', 'ipaddress'),  # ip地址
        ('domain', "domain"),  # 数据库服务器
    )

    type = models.CharField(choices=TYPE, max_length=50, default='ipaddress')


class DomainICPModel(IPDomainBaseModel):
    domain = models.CharField(blank=True, null=True, max_length=100)

    license = models.CharField(blank=True, null=True, max_length=100)
    content_type_name = models.CharField(blank=True, null=True, max_length=100)
    nature = models.CharField(blank=True, null=True, max_length=100)
    unit = models.CharField(blank=True, null=True, max_length=100)


class LocationModel(IPDomainBaseModel):
    org = models.CharField(blank=True, null=True, max_length=100)
    isp = models.CharField(blank=True, null=True, max_length=100)
    asname = models.CharField(blank=True, null=True, max_length=100)
    province_cn = models.CharField(blank=True, null=True, max_length=100)
    province_en = models.CharField(blank=True, null=True, max_length=100)
    country_cn = models.CharField(blank=True, null=True, max_length=100)
    country_en = models.CharField(blank=True, null=True, max_length=100)
    city_cn = models.CharField(blank=True, null=True, max_length=100)
    city_en = models.CharField(blank=True, null=True, max_length=100)
    scene_cn = models.CharField(blank=True, null=True, max_length=100)
    scene_en = models.CharField(blank=True, null=True, max_length=100)


class IPDomainPortBaseModel(WebBaseModel):
    ipdomain = models.CharField(blank=True, null=True, max_length=100)
    port = models.IntegerField(default=0)

    class Meta:
        abstract = True


class PortServiceModel(IPDomainPortBaseModel):
    transport = models.CharField(default="tcp", blank=True, null=True, max_length=100)
    service = models.CharField(blank=True, null=True, max_length=100)


class HttpBaseModel(IPDomainPortBaseModel):
    title = models.CharField(blank=True, null=True, max_length=100)
    status_code = models.IntegerField(default=0)
    path = models.CharField(blank=True, null=True, max_length=100)
    host = models.CharField(blank=True, null=True, max_length=100)
    body = models.TextField(blank=True, null=True)

    screenshot = models.CharField(blank=True, null=True, max_length=100)

    cert = models.TextField(blank=True, null=True)
    jarm = models.CharField(blank=True, null=True, max_length=100)


class HttpFavicon(IPDomainPortBaseModel):
    hash = models.CharField(blank=True, null=True, max_length=100)
    path = models.CharField(blank=True, null=True, max_length=100)  # 本地存储路径


class HttpComponentModel(IPDomainPortBaseModel):
    product_level = models.CharField(blank=True, null=True, max_length=100)
    product_type = DiyListField()
    product_vendor = models.CharField(blank=True, null=True, max_length=100)
    product_name_cn = models.CharField(blank=True, null=True, max_length=100)
    product_name_en = models.CharField(blank=True, null=True, max_length=100)
    version = models.CharField(blank=True, null=True, max_length=100)
    product_catalog = DiyListField()


class VulnerabilityModel(IPDomainPortBaseModel):
    name = models.TextField(blank=True, null=True)
    desc = models.TextField(blank=True, null=True)
