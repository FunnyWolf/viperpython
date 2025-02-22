# -*- coding: utf-8 -*-
# @File  : fofaclient.py
# @Date  : 2021/2/25
# @Desc  :

import requests
import urllib3

from Lib.timeapi import TimeAPI
from Lib.xcache import Xcache
from WebDatabase.Interface.dataset import DataSet
from WebDatabase.documents import IPDomainDocument, PortDocument, DNSRecordDocument, CertDocument, ComponentDocument, HttpBaseDocument, LocationDocument, \
    ServiceDocument

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

    def get_dataset(self, items) -> DataSet:
        dataset = DataSet()
        source = "Zoomeye"
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

            protocol = item.get("protocol")

            geoinfo = item.get("geoinfo")

            isp = geoinfo.get("isp")

            asname = geoinfo.get('organization')

            if isp is None:
                isp = asname

            webbase_dict = {
                'source': source,
                'update_time': update_time,
            }
            if domain:
                a = [ip]
            else:
                a = None
            if a:
                dnsrecord_obj: DNSRecordDocument = DNSRecordDocument()
                dnsrecord_obj.ipdomain = domain
                dnsrecord_obj.type = "A"
                dnsrecord_obj.value = a
                dnsrecord_obj.source = source
                dnsrecord_obj.update_time = update_time
                # dnsrecord_obj.data = item
                dataset.dnsrecordList.append(dnsrecord_obj)
            if cname:
                dnsrecord_obj: DNSRecordDocument = DNSRecordDocument()
                dnsrecord_obj.ipdomain = domain
                dnsrecord_obj.type = "CNAME"
                dnsrecord_obj.value = cname
                dnsrecord_obj.source = source
                dnsrecord_obj.update_time = update_time
                dataset.dnsrecordList.append(dnsrecord_obj)

            if domain is None:
                ipdomain = ip
            else:
                ipdomain = domain

            ipdomain_object = IPDomainDocument()
            ipdomain_object.ipdomain = ipdomain
            ipdomain_object.source = source
            ipdomain_object.update_time = update_time
            dataset.ipdomainList.append(ipdomain_object)

            webbase_location = {}
            webbase_location.update(webbase_dict)
            webbase_location['data'] = geoinfo

            location_obj = LocationDocument()
            location_obj.ipdomain = ipdomain
            location_obj.isp = isp
            location_obj.asname = asname

            location_obj.country_cn = geoinfo['country']['names']['zh-CN']
            location_obj.country_en = geoinfo['country']['names']['zh-CN']
            location_obj.province_cn = geoinfo['subdivisions']['names']['zh-CN']
            location_obj.province_en = geoinfo['subdivisions']['names']['zh-CN']
            location_obj.city_cn = geoinfo['city']['names']['zh-CN']
            location_obj.city_en = geoinfo['city']['names']['zh-CN']

            location_obj.source = source
            location_obj.update_time = update_time
            location_obj.data = geoinfo
            dataset.locationList.append(location_obj)

            port_object = PortDocument()
            port_object.ipdomain = ipdomain
            port_object.port = port
            port_object.alive = True
            port_object.source = source
            port_object.update_time = update_time
            dataset.portList.append(port_object)

            service_obj = ServiceDocument()
            service_obj.ipdomain = ipdomain
            service_obj.port = port
            service_obj.service = service_name
            service_obj.transport = item.get("transport")
            service_obj.response = response
            service_obj.source = source
            service_obj.update_time = update_time
            dataset.serviceList.append(service_obj)

            product_name = portinfo.get("app")
            product_version = portinfo.get("version")
            product_type = [portinfo.get("device")]

            component_object: ComponentDocument = ComponentDocument()
            component_object.ipdomain = ipdomain
            component_object.port = port
            component_object.product_name = product_name
            component_object.product_version = product_version
            component_object.product_type = product_type
            component_object.data = portinfo
            component_object.source = source
            component_object.update_time = update_time
            dataset.componentList.append(component_object)

            # Cert
            ssl = item.get('ssl')
            if ssl:
                cert_object = CertDocument()
                cert_object.ipdomain = ipdomain
                cert_object.port = port
                cert_object.cert = ssl
                cert_object.source = source
                cert_object.update_time = update_time
                dataset.certList.append(cert_object)

            # http
            if service_name.startswith("http"):
                # HttpBaseModel
                title = portinfo.get("title")
                if isinstance(title, list):
                    title = title[0]

                httpbase_object = HttpBaseDocument()
                httpbase_object.ipdomain = ipdomain
                httpbase_object.port = port
                httpbase_object.title = title
                httpbase_object.body = portinfo.get("banner")
                httpbase_object.source = source
                httpbase_object.update_time = update_time
                dataset.httpbaseList.append(httpbase_object)
        return dataset
