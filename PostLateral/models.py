from django.db import models

from Core.models import DiyDictField


# Create your models here.
class PortServiceModel(models.Model):
    hid = models.IntegerField(default=-1)
    proxy = DiyDictField(default={})
    update_time = models.IntegerField(default=0)
    port = models.IntegerField(default=0)
    banner = DiyDictField(default={})
    service = models.CharField(blank=True, null=True, max_length=100)


class CredentialModel(models.Model):
    username = models.CharField(blank=True, null=True, max_length=100)
    password = models.CharField(blank=True, null=True, max_length=100)  # 密码信息和hash信息
    password_type = models.CharField(blank=True, null=True, max_length=100)
    tag = DiyDictField(default={})  # 标识凭证的标签,如domain名称(mimikatz抓取的)或者url(laNage抓取的)
    source_module = models.CharField(blank=True, null=True, max_length=255)  # 凭证来源的模块loadpath
    host_ipaddress = models.CharField(blank=True, null=True, max_length=100)  # 凭证的主机ip地址(注意此信息不与core.host关联)
    desc = models.TextField(blank=True, null=True)  # 关于此凭证的说明


class VulnerabilityModel(models.Model):
    hid = models.IntegerField(default=-1)
    source_module_loadpath = models.CharField(blank=True, null=True, max_length=255)  # 密码信息和hash信息
    update_time = models.IntegerField(default=0)
    extra_data = DiyDictField(default={})  # 额外信息
    desc = models.TextField(blank=True, null=True)  # 关于凭证的说明
