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
    alive = models.BooleanField(default=True)
    color = models.CharField(blank=True, null=True, max_length=100)
    comment = models.TextField(blank=True, null=True)


class ServiceModel(PortBaseModel):
    transport = models.CharField(default="tcp", blank=True, null=True, max_length=100)
    service = models.CharField(blank=True, null=True, max_length=100, db_index=True)
    version = models.CharField(blank=True, null=True, max_length=100)
    response = models.TextField(blank=True, null=True)
    response_hash = models.CharField(blank=True, null=True, max_length=100)


class ComponentModel(PortBaseModel):
    product_name = models.CharField(blank=True, null=True, max_length=100, db_index=True)
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
    flag = models.BooleanField(default=False, db_index=True)
    domain = models.CharField(blank=True, null=True, max_length=100)
    name = models.CharField(blank=True, null=True, max_length=100)
    link = models.CharField(blank=True, null=True, max_length=100)


class HttpFaviconModel(PortBaseModel):
    hash = models.CharField(blank=True, null=True, max_length=100)
    content = models.TextField(blank=True, null=True)  # 存储base64后的文件


class WAFModel(PortBaseModel):
    flag = models.BooleanField(default=False, db_index=True)
    trigger_url = models.TextField(blank=True, null=True)
    name = models.CharField(blank=True, null=True, max_length=100)
    manufacturer = models.CharField(blank=True, null=True, max_length=100)


class VulnerabilityModel(PortBaseModel):
    tool = models.CharField(blank=True, null=True, max_length=100)
    name = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    severity = models.CharField(blank=True, null=True, max_length=100)  # info, low, medium, high, critical
    key = models.TextField(blank=True, null=True)  # 存储关键标签,比如CVE
    poc = models.TextField(blank=True, null=True)


# 企业信息
class CompanyBaseInfoModel(ProjectBaseModel, WebBaseModel):
    pid = models.CharField(blank=True, null=True, max_length=100)
    entType = models.CharField(blank=True, null=True, max_length=100)
    validityFrom = models.CharField(blank=True, null=True, max_length=100)
    openStatus = models.CharField(blank=True, null=True, max_length=100)  # "注销" "吊销"
    legalPerson = models.CharField(blank=True, null=True, max_length=100)
    logoWord = models.CharField(blank=True, null=True, max_length=100)
    titleName = models.CharField(blank=True, null=True, max_length=100)
    titleDomicile = models.TextField(blank=True, null=True)
    regCap = models.CharField(blank=True, null=True, max_length=100)
    regNo = models.CharField(blank=True, null=True, max_length=100)
    email = models.CharField(blank=True, null=True, max_length=100)
    website = models.CharField(blank=True, null=True, max_length=100)
    scope = models.TextField(blank=True, null=True)
    telephone = models.CharField(blank=True, null=True, max_length=100)


class CompanyICPModel(WebBaseModel):
    domain = models.CharField(blank=True, null=True, max_length=100)
    homeSite = models.CharField(blank=True, null=True, max_length=100)
    icpNo = models.CharField(blank=True, null=True, max_length=100)
    siteName = models.CharField(blank=True, null=True, max_length=100)


class CompanyAPPModel(WebBaseModel):
    pid = models.CharField(blank=True, null=True, max_length=100)
    name = models.CharField(blank=True, null=True, max_length=100)
    classify = models.CharField(blank=True, null=True, max_length=100)
    logo = models.CharField(blank=True, null=True, max_length=100)
    logoBrief = models.CharField(blank=True, null=True, max_length=100)


class CompanyWechatModel(WebBaseModel):
    pid = models.CharField(blank=True, null=True, max_length=100)
    principalName = models.CharField(blank=True, null=True, max_length=100)
    wechatId = models.CharField(blank=True, null=True, max_length=100)
    wechatName = models.CharField(blank=True, null=True, max_length=100)
    wechatIntruduction = models.TextField(blank=True, null=True)
    wechatLogo = models.CharField(blank=True, null=True, max_length=100)
    qrcode = models.CharField(blank=True, null=True, max_length=100)