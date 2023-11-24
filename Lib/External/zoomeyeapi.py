# -*- coding: utf-8 -*-
# @File  : fofaclient.py
# @Date  : 2021/2/25
# @Desc  :

import requests
import urllib3

from Lib.configs import DEFAULT_PROJECT_ID
from Lib.timeapi import TimeAPI
from Lib.xcache import Xcache
from WebDatabase.Handle.cert import Cert
from WebDatabase.Handle.component import Component
from WebDatabase.Handle.dnsrecord import DNSRecord
from WebDatabase.Handle.httpbase import HttpBase
from WebDatabase.Handle.ipdomain import IPDomain
from WebDatabase.Handle.location import Location
from WebDatabase.Handle.portservice import PortService

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ZoomeyeAPI(object):
    def __init__(self):
        self.key = None
        self.base_url = "https://api.zoomeye.org"
        self.user_info_url = "/resources-info"
        self.search_api_url = "/host/search"
        self.headers = {
            "API-KEY": self.key,
            "Content-Type": "application/json",
            'Connection': 'close'
        }

    def set_key(self, key):
        self.key = key

    def init_conf_from_cache(self):
        conf = Xcache.get_zoomeye_conf()
        if conf.get("alive") is not True:
            return False
        else:
            self.key = conf.get("key")
            return True

    def __http_get(self, url, params=None):
        try:
            headers = {
                "API-KEY": self.key,
                "Content-Type": "application/json",
                'Connection': 'close'
            }
            r = requests.get(url=url, params=params, verify=False, headers=headers)
            return r.json()
        except Exception as e:
            return None

    def get_userinfo(self):
        api_full_url = f"{self.base_url}{self.user_info_url}"

        res = self.__http_get(api_full_url)
        return res

    def is_alive(self):
        userdata = self.get_userinfo()
        if userdata is None:
            return False
        if userdata.get("code") == 60000:
            return True
        else:
            return False

    def get_data(self, query_str, page=1, size=100):
        api_full_url = f"{self.base_url}{self.search_api_url}"
        params = {'query': query_str, page: page}
        try:
            result = self.__http_get(api_full_url, params=params)
            code = result.get("code")
            total = result.get("total")
            available = result.get("available")
            matches = result.get("matches")
            facets = result.get("facets")

            format_results = []
            i = 0
            for onedict in matches:
                try:
                    ip = onedict.get("ip")
                    port = onedict.get("portinfo").get("port")
                    protocol = onedict.get("portinfo").get("service")
                    country_name = onedict.get("geoinfo").get("country").get("names").get("zh-CN")
                    as_organization = onedict.get("geoinfo").get("organization")
                    one_line = {
                        "index": i,
                        "ip": ip,
                        "port": port,
                        "protocol": protocol,
                        "country_name": country_name,
                        "as_organization": as_organization,
                    }
                except Exception as E:
                    continue
                format_results.append(one_line)
                i += 1
            return True, format_results
        except Exception as E:
            return False, str(E)

    def get_json_data(self, query_str, page=1, size=1000):
        api_full_url = f"{self.base_url}{self.search_api_url}"
        params = {'query': query_str, page: page}
        try:

            # debug hook start
            if Xcache.get_sample_data("ZOOMEYE_DOMAIN", query_str) is None:
                result = self.__http_get(api_full_url, params=params)
                Xcache.set_sample_data("ZOOMEYE_DOMAIN", query_str, result)
            else:
                result = Xcache.get_sample_data("ZOOMEYE_DOMAIN", query_str)
            # debug hook end

            # result = self.__http_get(api_full_url, params=params)
            code = result.get("code")
            total = result.get("total")
            available = result.get("available")
            matches = result.get("matches")
            facets = result.get("facets")
            return None, matches

        except Exception as E:
            return str(E), None

    def store_query_result(self, items, project_id=DEFAULT_PROJECT_ID, source={}):
        for item in items:
            format = '%Y-%m-%dT%H:%M:%S'
            update_time = TimeAPI.str_to_timestamp(item.get("timestamp"), format)

            ip = item.get("ip")
            domain = item.get("rdns")
            cname = None
            if "," in domain:  # 'mail.VWFAWEDL.com.cn.,mail1.vw-powertrain.com.,mailrelay.vw-transmission.com.,smg.vw-powertrain.com.,mail.volkswagen-faw.com.cn'
                cname = domain.split(",")
                domain = None

            portinfo = item.get('portinfo')

            port = portinfo.get("port")

            response = portinfo.get("banner")

            service_name = portinfo.get("service")
            if service_name == "https":
                service_name = "http/ssl"

            protocol = item.get("protocol")

            geoinfo = item.get("geoinfo")

            isp = geoinfo.get("isp")
            asname = geoinfo.get("oragnization")

            webbase_dict = {
                'source': source,
                'update_time': update_time,
            }
            if domain:
                a = [ip]
            else:
                a = None
            if a:
                DNSRecord.update_or_create(domain=domain, type="A", value=a, webbase_dict=webbase_dict)
            if cname:
                DNSRecord.update_or_create(domain=domain, type="CNAME", value=cname, webbase_dict=webbase_dict)

            if domain is None:
                ipdomain = ip
            else:
                ipdomain = domain

            IPDomain.update_or_create(project_id=project_id,
                                      ipdomain=ipdomain,
                                      webbase_dict=webbase_dict)
            webbase_location = {}
            webbase_location.update(webbase_dict)
            webbase_location['data'] = geoinfo

            geo_info = {'country_cn': geoinfo['country']['names']['zh-CN'],
                        'province_cn': geoinfo['subdivisions']['names']['zh-CN'],
                        'city_cn': geoinfo['city']['names']['zh-CN'], }

            Location.update_or_create(ipdomain=ipdomain,
                                      isp=isp,
                                      asname=asname,
                                      geo_info=geo_info,
                                      webbase_dict=webbase_location)

            PortService.update_or_create(ipdomain=ipdomain, port=port,
                                         response=response,
                                         response_hash=None,
                                         transport=item.get("transport"),
                                         service=service_name,
                                         version=None,
                                         webbase_dict=webbase_dict)

            product_name = portinfo.get("app")
            product_version = portinfo.get("version")
            product_type = [portinfo.get("device")]
            product_catalog = []
            product_dict_values = portinfo

            Component.update_or_create(ipdomain=ipdomain,
                                       port=port,
                                       product_name=product_name,
                                       product_version=product_version,
                                       product_type=product_type,
                                       product_catalog=product_catalog,
                                       product_dict_values=product_dict_values,
                                       webbase_dict=webbase_dict
                                       )

            # Cert
            ssl = item.get('ssl')
            if ssl:
                jarm_hash = None
                Cert.update_or_create(ipdomain=ipdomain, port=port,
                                      cert=ssl,
                                      jarm=jarm_hash,
                                      webbase_dict=webbase_dict
                                      )

            # http
            if service_name.startswith("http"):
                # HttpBaseModel
                title = portinfo.get("title")
                if isinstance(title, list):
                    title = title[0]

                HttpBase.update_or_create(ipdomain=ipdomain, port=port,
                                          title=title,
                                          status_code=None,
                                          header=None,
                                          body=portinfo.get("banner"),
                                          webbase_dict=webbase_dict
                                          )
