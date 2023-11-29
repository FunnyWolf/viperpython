from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.fields import HStoreField
from django.db import models

from Lib.log import logger


class ProjectBaseModel(models.Model):
    project_id = models.CharField(blank=True, null=True, max_length=100)  # uuid

    class Meta:
        abstract = True


class WebBaseModel(models.Model):
    source = models.JSONField(default=dict)  # 信息来源
    data = models.JSONField(default=dict)
    update_time = models.IntegerField(default=0)

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if self.pk:  # 已存在实例
            # 查询数据库获取旧值
            obj = self.__class__.objects.get(pk=self.pk)

            # 这里新增根据source进行优先级判断,存在高优先级数据则不更新
            # if (self.source == obj.source) and (self.update_time <= obj.update_time):
            if self.update_time <= obj.update_time:
                logger.debug(f"update bypass {self.source} {self.update_time}")
                return

        super().save(*args, **kwargs)


class IPDomainBaseModel(WebBaseModel):
    ipdomain = models.CharField(blank=True, null=True, max_length=100, db_index=True)  # 存放IP或domain

    class Meta:
        abstract = True


class PortBaseModel(IPDomainBaseModel):
    port = models.IntegerField(default=0, db_index=True)

    class Meta:
        abstract = True


class ProjectModel(ProjectBaseModel):
    name = models.TextField(blank=True, null=True)
    desc = models.TextField(blank=True, null=True)


class DNSRecordModel(IPDomainBaseModel):
    type = models.CharField(blank=True, null=True, max_length=10)  # A/CNAME
    value = ArrayField(models.CharField(blank=True, null=True, max_length=100), blank=True, default=list)
    # value = models.JSONField(default=list)


class IPDomainModel(IPDomainBaseModel, ProjectBaseModel):
    pass


class DomainICPModel(IPDomainBaseModel):
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
    # geo_info = models.JSONField(default=dict)


class PortModel(PortBaseModel):
    pass


class ServiceModel(PortBaseModel):
    transport = models.CharField(default="tcp", blank=True, null=True, max_length=100)
    service = models.CharField(blank=True, null=True, max_length=100)
    version = models.CharField(blank=True, null=True, max_length=100)
    response = models.TextField(blank=True, null=True)
    response_hash = models.CharField(blank=True, null=True, max_length=100)


class ComponentModel(PortBaseModel):
    product_name = models.CharField(blank=True, null=True, max_length=100)
    product_version = models.CharField(blank=True, null=True, max_length=100)
    product_type = ArrayField(models.CharField(blank=True, null=True, max_length=100), blank=True)
    product_catalog = ArrayField(models.CharField(blank=True, null=True, max_length=100), blank=True)
    product_dict_values = HStoreField(default=dict)
    # product_type = models.JSONField(default=list)
    # product_catalog = models.JSONField(default=list)
    # product_dict_values = models.JSONField(default=dict)


class CertModel(PortBaseModel):
    cert = models.TextField(blank=True, null=True)
    jarm = models.CharField(blank=True, null=True, max_length=100)
    subject = HStoreField(default=dict)


class ScreenshotModel(PortBaseModel):
    content = models.TextField(blank=True, null=True)  # 存储base64后的文件


class HttpBaseModel(PortBaseModel):
    title = models.CharField(blank=True, null=True, max_length=100)
    status_code = models.IntegerField(default=0, blank=True, null=True, )
    header = models.TextField(blank=True, null=True)
    body = models.TextField(blank=True, null=True)


class CDNModel(IPDomainBaseModel):
    flag = models.BooleanField(default=False)


class HttpFaviconModel(PortBaseModel):
    hash = models.CharField(blank=True, null=True, max_length=100)
    content = models.TextField(blank=True, null=True)  # 存储base64后的文件


# product_level = models.CharField(blank=True, null=True, max_length=100)
# product_vendor = models.CharField(blank=True, null=True, max_length=100)
# product_name_cn = models.CharField(blank=True, null=True, max_length=100)
# product_name_en = models.CharField(blank=True, null=True, max_length=100)
# product_version = models.CharField(blank=True, null=True, max_length=100)

class WAFModel(PortBaseModel):
    flag = models.BooleanField(default=False)
    trigger_url = models.TextField(blank=True, null=True)
    name = models.CharField(blank=True, null=True, max_length=100)
    manufacturer = models.CharField(blank=True, null=True, max_length=100)


class VulnerabilityModel(PortBaseModel):
    name = models.TextField(blank=True, null=True)
    desc = models.TextField(blank=True, null=True)
