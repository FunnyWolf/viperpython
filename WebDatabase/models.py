from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.fields import HStoreField
from django.db import models

from Lib.log import logger


# Create your models here.
class WebBaseModel(models.Model):
    project_id = models.CharField(blank=True, null=True, max_length=100)  # uuid
    source = models.CharField(blank=True, null=True, max_length=100)  # 信息来源
    source_key = models.CharField(blank=True, null=True, max_length=100)  # 信息来源
    data = models.JSONField()
    update_time = models.IntegerField(default=0)

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if self.pk:  # 已存在实例
            # 查询数据库获取旧值
            obj = self.__class__.objects.get(pk=self.pk)
            if self.update_time <= obj.update_time:
                logger.info("旧值更新时间大于等于新值,不更新")
                return

        super().save(*args, **kwargs)


class IPDomainBaseModel(WebBaseModel):
    ip = models.CharField(blank=True, null=True, max_length=100)
    domain = models.CharField(blank=True, null=True, max_length=100)

    class Meta:
        abstract = True


class IPPortBaseModel(IPDomainBaseModel):
    port = models.IntegerField(default=0)

    class Meta:
        abstract = True


class DNSRecordModel(IPDomainBaseModel):
    type = models.CharField(blank=True, null=True, max_length=100)
    value = models.CharField(blank=True, null=True, max_length=100)


# 存储Project相关信息
class ProjectModel(models.Model):
    project_id = models.CharField(blank=True, null=True, max_length=100)  # uuid
    name = models.TextField(blank=True, null=True)
    desc = models.TextField(blank=True, null=True)


class IPDomainModel(IPDomainBaseModel):
    pass


class DomainICPModel(IPDomainBaseModel):
    domain_icp = models.CharField(blank=True, null=True, max_length=100)  # 存储注册ICP的域名
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


class PortServiceModel(IPPortBaseModel):
    transport = models.CharField(default="tcp", blank=True, null=True, max_length=100)
    service = models.CharField(blank=True, null=True, max_length=100)
    version = models.CharField(blank=True, null=True, max_length=100)


class HttpBaseModel(IPPortBaseModel):
    title = models.CharField(blank=True, null=True, max_length=100)
    status_code = models.IntegerField(default=0)
    response = models.TextField(blank=True, null=True)
    header = models.TextField(blank=True, null=True)
    body = models.TextField(blank=True, null=True)


class CertModel(IPPortBaseModel):
    cert = models.TextField(blank=True, null=True)
    jarm = models.CharField(blank=True, null=True, max_length=100)


class ScreenshotModel(IPPortBaseModel):
    content = models.TextField(blank=True, null=True)  # 存储base64后的文件


class HttpFaviconModel(IPPortBaseModel):
    hash = models.CharField(blank=True, null=True, max_length=100)
    content = models.TextField(blank=True, null=True)  # 存储base64后的文件


# product_level = models.CharField(blank=True, null=True, max_length=100)
# product_vendor = models.CharField(blank=True, null=True, max_length=100)
# product_name_cn = models.CharField(blank=True, null=True, max_length=100)
# product_name_en = models.CharField(blank=True, null=True, max_length=100)
# product_version = models.CharField(blank=True, null=True, max_length=100)
class ComponentModel(IPPortBaseModel):
    product_dict_values = HStoreField(default=dict)
    product_type = ArrayField(models.CharField(blank=True, null=True, max_length=100), blank=True)
    product_catalog = ArrayField(models.CharField(blank=True, null=True, max_length=100), blank=True)


class VulnerabilityModel(IPPortBaseModel):
    name = models.TextField(blank=True, null=True)
    desc = models.TextField(blank=True, null=True)
