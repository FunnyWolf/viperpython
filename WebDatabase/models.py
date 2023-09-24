from django.db import models

from Core.models import DiyDictField


# Create your models here.
class IPDomainModel(models.Model):
    TYPE = (
        ('ipaddress', 'ipaddress'),  # ip地址
        ('domain', "domain"),  # 数据库服务器
    )

    ipdomain = models.CharField(blank=True, null=True, max_length=100)
    type = models.CharField(choices=TYPE, max_length=50, default='ipaddress')
    source = models.CharField(blank=True, null=True, max_length=100)  # 信息来源
    data = DiyDictField(default={})
    update_time = models.IntegerField(default=0)


class PortServiceModel(models.Model):
    ipdomain = models.CharField(blank=True, null=True, max_length=100)
    port = models.IntegerField(default=0)
    service = models.CharField(blank=True, null=True, max_length=100)
    source = models.CharField(blank=True, null=True, max_length=100)  # 信息来源
    data = DiyDictField(default={})
    update_time = models.IntegerField(default=0)


class WebInfomationModel(models.Model):
    ipdomain = models.CharField(blank=True, null=True, max_length=100)
    port = models.IntegerField(default=0)
    title = models.CharField(blank=True, null=True, max_length=100)
    code = models.IntegerField(default=0)
    html = models.TextField(blank=True, null=True)
    screenshot = models.CharField(blank=True, null=True, max_length=100)
    sslfile = models.CharField(blank=True, null=True, max_length=100)
    source = models.CharField(blank=True, null=True, max_length=100)  # 信息来源
    data = DiyDictField(default={})
    update_time = models.IntegerField(default=0)


class WebFingerprintModel(models.Model):
    ipdomain = models.CharField(blank=True, null=True, max_length=100)
    port = models.IntegerField(default=0)
    plugin = models.CharField(blank=True, null=True, max_length=100)
    source = models.CharField(blank=True, null=True, max_length=100)  # 信息来源
    data = DiyDictField(default={})
    update_time = models.IntegerField(default=0)


class VulnerabilityModel(models.Model):
    ipdomain = models.CharField(blank=True, null=True, max_length=100)
    port = models.IntegerField(default=0)
    name = models.TextField(blank=True, null=True)
    desc = models.TextField(blank=True, null=True)
    source = models.CharField(blank=True, null=True, max_length=100)  # 信息来源
    data = DiyDictField(default={})
    update_time = models.IntegerField(default=0)


class DNSRecordModel(models.Model):
    ip = models.CharField(blank=True, null=True, max_length=100)
    domain = models.CharField(blank=True, null=True, max_length=100)
    type = models.CharField(blank=True, null=True, max_length=100)
    value = models.CharField(blank=True, null=True, max_length=100)
    source = models.CharField(blank=True, null=True, max_length=100)  # 信息来源
    data = DiyDictField(default={})
    update_time = models.IntegerField(default=0)


class TargetModel(models.Model):
    ipdomain = models.CharField(blank=True, null=True, max_length=100)
    name = models.TextField(blank=True, null=True)
    desc = models.TextField(blank=True, null=True)
    source = models.CharField(blank=True, null=True, max_length=100)  # 信息来源
    data = DiyDictField(default={})
    update_time = models.IntegerField(default=0)
