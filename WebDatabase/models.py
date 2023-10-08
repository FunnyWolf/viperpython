from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.fields import HStoreField
from django.db import models


# Create your models here.
class WebBaseModel(models.Model):
    source = models.CharField(blank=True, null=True, max_length=100)  # 信息来源
    source_key = models.CharField(blank=True, null=True, max_length=100)  # 信息来源
    data = models.JSONField()
    update_time = models.IntegerField(default=0)

    class Meta:
        abstract = True


class IPDomainBaseModel(WebBaseModel):
    ipdomain = models.CharField(blank=True, null=True, max_length=100)

    class Meta:
        abstract = True


class IPDomainPortBaseModel(WebBaseModel):
    ipdomain = models.CharField(blank=True, null=True, max_length=100)
    port = models.IntegerField(default=0)

    class Meta:
        abstract = True


class DNSRecordModel(WebBaseModel):
    ip = models.CharField(blank=True, null=True, max_length=100)
    domain = models.CharField(blank=True, null=True, max_length=100)
    type = models.CharField(blank=True, null=True, max_length=100)
    value = models.CharField(blank=True, null=True, max_length=100)


# 存储目标相关信息
class TargetModel(IPDomainBaseModel):
    name = models.TextField(blank=True, null=True)
    desc = models.TextField(blank=True, null=True)


class IPDomainModel(IPDomainBaseModel):
    TYPE = (
        ('ip', 'ip'),  # ip地址
        ('domain', "domain"),  # 数据库服务器
    )

    type = models.CharField(choices=TYPE, max_length=50, default='ip')


class DomainICPModel(IPDomainBaseModel):
    domain = models.CharField(blank=True, null=True, max_length=100)
    unit = models.CharField(blank=True, null=True, max_length=100)
    license = models.CharField(blank=True, null=True, max_length=100)


# province_cn = models.CharField(blank=True, null=True, max_length=100)
# province_en = models.CharField(blank=True, null=True, max_length=100)
# country_cn = models.CharField(blank=True, null=True, max_length=100)
# country_en = models.CharField(blank=True, null=True, max_length=100)
# city_cn = models.CharField(blank=True, null=True, max_length=100)
# city_en = models.CharField(blank=True, null=True, max_length=100)
# scene_cn = models.CharField(blank=True, null=True, max_length=100)
# scene_en = models.CharField(blank=True, null=True, max_length=100)
class LocationModel(IPDomainBaseModel):
    isp = models.CharField(blank=True, null=True, max_length=100)
    asname = models.CharField(blank=True, null=True, max_length=100)

    geo_info = HStoreField(default=dict)


class PortServiceModel(IPDomainPortBaseModel):
    transport = models.CharField(default="tcp", blank=True, null=True, max_length=100)
    service = models.CharField(blank=True, null=True, max_length=100)
    version = models.CharField(blank=True, null=True, max_length=100)


class HttpBaseModel(IPDomainPortBaseModel):
    title = models.CharField(blank=True, null=True, max_length=100)
    status_code = models.IntegerField(default=0)
    response = models.TextField(blank=True, null=True)
    header = models.TextField(blank=True, null=True)
    body = models.TextField(blank=True, null=True)


class HttpCertModel(IPDomainPortBaseModel):
    cert = models.TextField(blank=True, null=True)
    jarm = models.CharField(blank=True, null=True, max_length=100)


class HttpScreenshotModel(IPDomainPortBaseModel):
    content = models.TextField(blank=True, null=True)  # 存储base64后的文件


class HttpFaviconModel(IPDomainPortBaseModel):
    hash = models.CharField(blank=True, null=True, max_length=100)
    content = models.TextField(blank=True, null=True)  # 存储base64后的文件


# product_level = models.CharField(blank=True, null=True, max_length=100)
# product_vendor = models.CharField(blank=True, null=True, max_length=100)
# product_name_cn = models.CharField(blank=True, null=True, max_length=100)
# product_name_en = models.CharField(blank=True, null=True, max_length=100)
# product_version = models.CharField(blank=True, null=True, max_length=100)
class HttpComponentModel(IPDomainPortBaseModel):
    product_dict_values = HStoreField(default=dict)
    product_type = ArrayField(models.CharField(blank=True, null=True, max_length=100), blank=True)
    product_catalog = ArrayField(models.CharField(blank=True, null=True, max_length=100), blank=True)


class VulnerabilityModel(IPDomainPortBaseModel):
    name = models.TextField(blank=True, null=True)
    desc = models.TextField(blank=True, null=True)
