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
            return "Intranet"
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
