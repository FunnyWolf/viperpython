from django.db import models


class ProjectMetaModel(models.Model):
    project_id = models.CharField(blank=True, null=True, max_length=100)  # uuid

    class Meta:
        abstract = True


class CompanyMetaModel(models.Model):
    company_name = models.CharField(blank=True, null=True, max_length=100)  # key

    class Meta:
        abstract = True


class WebMetaModel(models.Model):
    source = models.CharField(blank=True, null=True, max_length=100)  # 信息来源
    data = models.JSONField(default=dict)
    update_time = models.IntegerField(default=0)

    class Meta:
        abstract = True


class ClueMetaModel(models.Model):
    cid = models.CharField(blank=True, null=True, max_length=100)  # uuid
    exact = models.BooleanField(default=True)

    class Meta:
        abstract = True


class IPDomainMetaModel(models.Model):
    ipdomain = models.CharField(blank=True, null=True, max_length=100, db_index=True)  # 存放IP或domain

    class Meta:
        abstract = True


class PortMetaModel(models.Model):
    port = models.IntegerField(default=0, db_index=True)

    class Meta:
        abstract = True


# class ProjectModel(ProjectMetaModel):
#     name = models.TextField(blank=True, null=True)
#     desc = models.TextField(blank=True, null=True)


# value = ArrayField(models.CharField(blank=True, null=True, max_length=100), blank=True, default=list)
# class DNSRecordModel(IPDomainMetaModel, WebMetaModel):
#     type = models.CharField(blank=True, null=True, max_length=10)  # A/CNAME
#     value = models.JSONField(default=list)
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if not self.value:  # A或CNAME有数据
#                 return
#         if self.value is None or self.value == "":
#             self.value = []
#         super().save(*args, **kwargs)


# class IPDomainModel(IPDomainMetaModel, ProjectMetaModel, CompanyMetaModel, WebMetaModel):
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.company_name is None:
#                 self.company_name = obj.company_name
#
#         super().save(*args, **kwargs)


# class DomainICPModel(WebMetaModel):
#     domain = models.CharField(blank=True, null=True, max_length=100)
#     unit = models.CharField(blank=True, null=True, max_length=100)
#     license = models.CharField(blank=True, null=True, max_length=100)


# class LocationModel(IPDomainMetaModel, WebMetaModel):
#     isp = models.CharField(blank=True, null=True, max_length=100)
#     asname = models.CharField(blank=True, null=True, max_length=100)
#
#     scene_cn = models.CharField(blank=True, null=True, max_length=100)
#     scene_en = models.CharField(blank=True, null=True, max_length=100)
#
#     country_cn = models.CharField(blank=True, null=True, max_length=100)
#     country_en = models.CharField(blank=True, null=True, max_length=100)
#     province_cn = models.CharField(blank=True, null=True, max_length=100)
#     province_en = models.CharField(blank=True, null=True, max_length=100)
#     city_cn = models.CharField(blank=True, null=True, max_length=100)
#     city_en = models.CharField(blank=True, null=True, max_length=100)
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.isp is None:
#                 self.isp = obj.isp
#             if self.asname is None:
#                 self.asname = obj.asname
#             if self.scene_cn is None:
#                 self.scene_cn = obj.scene_cn
#             if self.scene_en is None:
#                 self.scene_en = obj.scene_en
#             if self.country_cn is None:
#                 self.country_cn = obj.country_cn
#             if self.country_en is None:
#                 self.country_en = obj.country_en
#             if self.province_cn is None:
#                 self.province_cn = obj.province_cn
#             if self.province_en is None:
#                 self.province_en = obj.province_en
#             if self.city_cn is None:
#                 self.city_cn = obj.city_cn
#             if self.city_en is None:
#                 self.city_en = obj.city_en
#
#         super().save(*args, **kwargs)


# class PortModel(IPDomainMetaModel, PortMetaModel, WebMetaModel):
#     alive = models.BooleanField(default=True)
#     color = models.CharField(blank=True, null=True, max_length=100)
#     comment = models.TextField(blank=True, null=True)
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.color is None:
#                 self.color = obj.color
#             if self.comment is None:
#                 self.comment = obj.comment
#
#         super().save(*args, **kwargs)


# class ServiceModel(IPDomainMetaModel, PortMetaModel, WebMetaModel):
#     transport = models.CharField(default="tcp", blank=True, null=True, max_length=100)
#     service = models.CharField(blank=True, null=True, max_length=100, db_index=True)
#     version = models.CharField(blank=True, null=True, max_length=100)
#     response = models.TextField(blank=True, null=True)
#     response_hash = models.CharField(blank=True, null=True, max_length=100)
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.transport is None:
#                 self.transport = obj.transport
#             if self.service is None:
#                 self.service = obj.service
#             if self.version is None:
#                 self.version = obj.version
#             if self.response is None:
#                 self.response = obj.response
#             if self.response_hash is None:
#                 self.response_hash = obj.response_hash
#
#         super().save(*args, **kwargs)


# product_type = ArrayField(models.CharField(blank=True, null=True, max_length=100), blank=True)
# product_catalog = ArrayField(models.CharField(blank=True, null=True, max_length=100), blank=True)
# product_dict_values = HStoreField(default=dict)
# class ComponentModel(IPDomainMetaModel, PortMetaModel, WebMetaModel):
#     product_name = models.CharField(blank=True, null=True, max_length=100, db_index=True)
#     product_version = models.CharField(blank=True, null=True, max_length=100)
#     product_extrainfo = models.CharField(blank=True, null=True, max_length=100)
#     product_type = models.JSONField(default=list, null=True, blank=True)
#     product_catalog = models.JSONField(default=list, null=True, blank=True)
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.product_name is None:
#                 self.product_name = obj.product_name
#             if self.product_version is None:
#                 self.product_version = obj.product_version
#             if self.product_extrainfo is None:
#                 self.product_extrainfo = obj.product_extrainfo
#             if not self.product_type:
#                 self.product_type = obj.product_type
#             if not self.product_catalog:
#                 self.product_catalog = obj.product_catalog
#
#         if self.product_catalog is None or self.product_catalog == "":
#             self.product_catalog = []
#         if self.product_type is None or self.product_type == "":
#             self.product_type = []
#
#         super().save(*args, **kwargs)


# subject = HStoreField(default=dict)
# class CertModel(IPDomainMetaModel, PortMetaModel, WebMetaModel):
#     cert = models.TextField(blank=True, null=True)
#     jarm = models.CharField(blank=True, null=True, max_length=100)
#     subject = models.JSONField(default=dict)
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.cert is None:
#                 self.cert = obj.cert
#             if self.jarm is None:
#                 self.jarm = obj.jarm
#             if not self.subject:
#                 self.subject = obj.subject
#
#         if self.subject is None or self.subject == "":
#             self.subject = []
#
#         super().save(*args, **kwargs)


# class ScreenshotModel(IPDomainMetaModel, PortMetaModel, WebMetaModel):
#     content = models.TextField(blank=True, null=True)  # 存储base64后的文件
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.content is None:
#                 self.content = obj.content
#
#         super().save(*args, **kwargs)


# class HttpBaseModel(IPDomainMetaModel, PortMetaModel, WebMetaModel):
#     title = models.CharField(blank=True, null=True, max_length=100)
#     status_code = models.IntegerField(default=0, blank=True, null=True, )
#     header = models.TextField(blank=True, null=True)
#     body = models.TextField(blank=True, null=True)
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.title is None:
#                 self.title = obj.title
#             if self.status_code == 0:
#                 self.status_code = obj.status_code
#             if self.header is None:
#                 self.header = obj.header
#             if self.body is None:
#                 self.body = obj.body
#
#         super().save(*args, **kwargs)


# class HttpFaviconModel(IPDomainMetaModel, PortMetaModel, WebMetaModel):
#     hash = models.CharField(blank=True, null=True, max_length=100)
#     content = models.TextField(blank=True, null=True)  # 存储base64后的文件
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.hash is None:
#                 self.hash = obj.hash
#             if self.content is None:
#                 self.content = obj.content
#
#         super().save(*args, **kwargs)


# class CDNModel(IPDomainMetaModel, WebMetaModel):
#     flag = models.BooleanField(default=False, db_index=True)
#     domain = models.CharField(blank=True, null=True, max_length=100)
#     name = models.CharField(blank=True, null=True, max_length=100)
#     link = models.CharField(blank=True, null=True, max_length=100)
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.domain is None:
#                 self.domain = obj.domain
#             if self.name is None:
#                 self.name = obj.name
#             if self.link is None:
#                 self.link = obj.link
#
#         super().save(*args, **kwargs)


# class WAFModel(IPDomainMetaModel, PortMetaModel, WebMetaModel):
#     flag = models.BooleanField(default=False, db_index=True)
#     trigger_url = models.TextField(blank=True, null=True)
#     name = models.CharField(blank=True, null=True, max_length=100)
#     manufacturer = models.CharField(blank=True, null=True, max_length=100)
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.trigger_url is None:
#                 self.trigger_url = obj.trigger_url
#             if self.name is None:
#                 self.name = obj.name
#             if self.manufacturer is None:
#                 self.manufacturer = obj.manufacturer
#         super().save(*args, **kwargs)


# class VulnerabilityModel(IPDomainMetaModel, PortMetaModel, WebMetaModel):
#     name = models.TextField(blank=True, null=True)  # 漏洞名称
#     description = models.TextField(blank=True, null=True)
#     severity = models.CharField(blank=True, null=True, max_length=100)  # info, low, medium, high, critical
#
#     template_id = models.TextField(blank=True, null=True)  # 存储关键标签,比如CVE或弱密码等
#     matched_at = models.TextField(blank=True, null=True)
#     reference = models.JSONField(default=list)
#     request = models.TextField(blank=True, null=True)
#     response = models.TextField(blank=True, null=True)
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.name is None:
#                 self.name = obj.name
#             if self.description is None:
#                 self.description = obj.description
#             if self.severity is None:
#                 self.severity = obj.severity
#
#             if self.template_id is None:
#                 self.template_id = obj.template_id
#
#             if self.matched_at is None:
#                 self.matched_at = obj.matched_at
#
#             if not self.reference:
#                 self.reference = obj.reference
#             if self.request is None:
#                 self.request = obj.request
#             if self.response is None:
#                 self.response = obj.response
#
#         if self.reference is None or self.reference == "":
#             self.reference = []
#
#         super().save(*args, **kwargs)


# 企业信息
# class CompanyBaseInfoModel(ProjectMetaModel, CompanyMetaModel, WebMetaModel):
#     pid = models.CharField(blank=True, null=True, max_length=100)
#     entType = models.CharField(blank=True, null=True, max_length=100)
#     validityFrom = models.CharField(blank=True, null=True, max_length=100)
#     openStatus = models.CharField(blank=True, null=True, max_length=100)  # "注销" "吊销"
#     legalPerson = models.CharField(blank=True, null=True, max_length=100)
#     logoWord = models.CharField(blank=True, null=True, max_length=100)
#     titleName = models.CharField(blank=True, null=True, max_length=100)
#     titleDomicile = models.TextField(blank=True, null=True)
#     regCap = models.CharField(blank=True, null=True, max_length=100)
#     regNo = models.CharField(blank=True, null=True, max_length=100)
#     email = models.CharField(blank=True, null=True, max_length=100)
#     website = models.CharField(blank=True, null=True, max_length=100)
#     scope = models.TextField(blank=True, null=True)
#     telephone = models.CharField(blank=True, null=True, max_length=100)
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.pid is None:
#                 self.pid = obj.pid
#             if self.entType is None:
#                 self.entType = obj.entType
#             if self.validityFrom is None:
#                 self.validityFrom = obj.validityFrom
#             if self.openStatus is None:
#                 self.openStatus = obj.openStatus
#             if self.legalPerson is None:
#                 self.legalPerson = obj.legalPerson
#             if self.logoWord is None:
#                 self.logoWord = obj.logoWord
#             if self.titleName is None:
#                 self.titleName = obj.titleName
#             if self.titleDomicile is None:
#                 self.titleDomicile = obj.titleDomicile
#             if self.regCap is None:
#                 self.regCap = obj.regCap
#             if self.regNo is None:
#                 self.regNo = obj.regNo
#             if self.email is None:
#                 self.email = obj.email
#             if self.website is None:
#                 self.website = obj.website
#             if self.scope is None:
#                 self.scope = obj.scope
#             if self.telephone is None:
#                 self.telephone = obj.telephone
#
#         super().save(*args, **kwargs)


# class CompanyICPModel(ProjectMetaModel, CompanyMetaModel, WebMetaModel):
#     pid = models.CharField(blank=True, null=True, max_length=100)
#     domain = models.CharField(blank=True, null=True, max_length=100)
#     homeSite = models.CharField(blank=True, null=True, max_length=100)
#     icpNo = models.CharField(blank=True, null=True, max_length=100)
#     siteName = models.CharField(blank=True, null=True, max_length=100)
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.pid is None:
#                 self.pid = obj.pid
#             if self.domain is None:
#                 self.domain = obj.domain
#             if self.homeSite is None:
#                 self.homeSite = obj.homeSite
#             if self.icpNo is None:
#                 self.icpNo = obj.icpNo
#             if self.siteName is None:
#                 self.siteName = obj.siteName
#
#         super().save(*args, **kwargs)


# class CompanyAPPModel(ProjectMetaModel, CompanyMetaModel, WebMetaModel):
#     pid = models.CharField(blank=True, null=True, max_length=100)
#     name = models.CharField(blank=True, null=True, max_length=100)
#     classify = models.CharField(blank=True, null=True, max_length=1024)
#     logo = models.CharField(blank=True, null=True, max_length=1024)
#     logoBrief = models.CharField(blank=True, null=True, max_length=1024)
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.pid is None:
#                 self.pid = obj.pid
#             if self.name is None:
#                 self.name = obj.name
#             if self.classify is None:
#                 self.classify = obj.classify
#             if self.logo is None:
#                 self.logo = obj.logo
#             if self.logoBrief is None:
#                 self.logoBrief = obj.logoBrief
#
#         super().save(*args, **kwargs)


# class CompanyWechatModel(ProjectMetaModel, CompanyMetaModel, WebMetaModel):
#     pid = models.CharField(blank=True, null=True, max_length=100)
#     principalName = models.CharField(blank=True, null=True, max_length=100)
#     wechatId = models.CharField(blank=True, null=True, max_length=100)
#     wechatName = models.CharField(blank=True, null=True, max_length=100)
#     wechatIntruduction = models.TextField(blank=True, null=True)
#     wechatLogo = models.CharField(blank=True, null=True, max_length=1024)
#     qrcode = models.CharField(blank=True, null=True, max_length=1024)
#
#     def save(self, *args, **kwargs):
#         if self.pk:  # 已存在实例
#             # 查询数据库获取旧值
#             obj = self.__class__.objects.get(pk=self.pk)
#
#             if self.pid is None:
#                 self.pid = obj.pid
#             if self.principalName is None:
#                 self.principalName = obj.principalName
#             if self.wechatId is None:
#                 self.wechatId = obj.wechatId
#             if self.wechatName is None:
#                 self.wechatName = obj.wechatName
#             if self.wechatIntruduction is None:
#                 self.wechatIntruduction = obj.wechatIntruduction
#             if self.wechatLogo is None:
#                 self.wechatLogo = obj.wechatLogo
#             if self.qrcode is None:
#                 self.qrcode = obj.qrcode
#
#         super().save(*args, **kwargs)


# # Clue
# class ClueCompanyModel(ProjectMetaModel, ClueMetaModel, WebMetaModel):
#     name = models.CharField(blank=True, null=True, max_length=100)


# class ClueFaviconModel(ProjectMetaModel, ClueMetaModel, WebMetaModel):
#     hash = models.CharField(blank=True, null=True, max_length=100)
#     content = models.TextField(blank=True, null=True)  # 存储base64后的文件


# class ClueCertModel(ProjectMetaModel, ClueMetaModel, WebMetaModel):
#     cert = models.TextField(blank=True, null=True)
#     jarm = models.CharField(blank=True, null=True, max_length=100)
#     subject = models.JSONField(default=dict)


# class ClueHttpTitleModel(ProjectMetaModel, ClueMetaModel, WebMetaModel):
#     title = models.CharField(blank=True, null=True, max_length=100)
