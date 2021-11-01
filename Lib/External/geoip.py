# -*- coding: utf-8 -*-
# @File  : geoip.py
# @Date  : 2021/2/25
# @Desc  :
import os

import geoip2.database
from django.conf import settings


class Geoip2(object):
    def __init__(self):
        city_mmdb_dir = os.path.join(settings.BASE_DIR, 'STATICFILES', 'STATIC', 'GeoLite2-City.mmdb')
        self.city_reader = geoip2.database.Reader(city_mmdb_dir)
        asn_mmdb_dir = os.path.join(settings.BASE_DIR, 'STATICFILES', 'STATIC', 'GeoLite2-ASN.mmdb')
        self.asn_reader = geoip2.database.Reader(asn_mmdb_dir)

        country_mmdb_dir = os.path.join(settings.BASE_DIR, 'STATICFILES', 'STATIC', 'GeoLite2-Country.mmdb')
        self.country_reader = geoip2.database.Reader(country_mmdb_dir)

    def get_geo(self, ip, lang="zh-CN"):
        try:
            response = self.country_reader.country(ip)
        except Exception as E:
            if lang == "zh-CN":
                return ["内网IP", "", "", "本地"]
            else:
                return ["Intranet", "", "", "Local"]

        try:
            country = response.country.get(lang)
        except Exception as E:
            try:
                country = response.country.get("en")
            except Exception as E:
                country = ""

        try:
            city = self.city_reader.city(ip).city.names.get(lang)
        except Exception as E:
            try:
                city = self.city_reader.city(ip).city.names.get("en")
            except Exception as E:
                city = ""
        try:
            province = self.city_reader.city(ip).subdivisions.most_specific.names.get(lang)
        except Exception as E:
            try:
                province = self.city_reader.city(ip).subdivisions.most_specific.names.get("en")
            except Exception as E:
                province = ""

        try:
            isp = self.asn_reader.asn(ip).autonomous_system_organization
        except Exception as E:
            isp = ""
        return [country, province, city, isp]

    def get_geo_str(self, ip, lang="zh-CN"):
        return " ".join(self.get_geo(ip, lang))


geoip2_interface = Geoip2()
