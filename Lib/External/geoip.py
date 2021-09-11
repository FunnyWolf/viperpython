# -*- coding: utf-8 -*-
# @File  : geoip.py
# @Date  : 2021/2/25
# @Desc  :
import os

import geoip2.database
from django.conf import settings

from Lib.log import logger
from Lib.xcache import Xcache


class Geoip(object):
    def __init__(self):
        pass

    @staticmethod
    def get_city(ip):
        result = Xcache.get_city_reader_cache(ip)
        if result is not None:
            return result
        city_mmdb_dir = os.path.join(settings.BASE_DIR, 'STATICFILES', 'STATIC', 'GeoLite2-City.mmdb')
        city_reader = geoip2.database.Reader(city_mmdb_dir)

        try:
            response = city_reader.city(ip)
        except Exception as _:
            Xcache.set_city_reader_cache(ip, "Intranet")
            return "局域网"
        country = ""
        try:
            country = response.country.name
            country = response.country.names['en']
        except Exception as E:
            logger.exception(E)
        if country is None:
            country = ""
        subdivision = ""
        try:
            subdivision = response.subdivisions.most_specific.name
            subdivision = response.subdivisions.most_specific.names['en']
        except Exception as _:
            pass
        if subdivision is None:
            subdivision = ""
        city = ""
        try:
            city = response.city.name
            city = response.city.names['en']
        except Exception as _:
            pass
        if city is None:
            city = ""
        result = f"{country} {subdivision} {city}"
        Xcache.set_city_reader_cache(ip, result)
        return result

    @staticmethod
    def get_asn(ip):

        asn_reader = Xcache.get_asn_reader_cache(ip)
        if asn_reader is not None:
            return asn_reader

        asn_mmdb_dir = os.path.join(settings.BASE_DIR, 'STATICFILES', 'STATIC', 'GeoLite2-ASN.mmdb')
        asn_reader = geoip2.database.Reader(asn_mmdb_dir)

        try:
            response = asn_reader.asn(ip)
        except Exception as _:
            Xcache.set_asn_reader_cache(ip, "")
            return ""
        Xcache.set_asn_reader_cache(ip, response.autonomous_system_organization)
        return response.autonomous_system_organization
