# -*- coding: utf-8 -*-
# @File  : fofaclient.py
# @Date  : 2021/2/25
# @Desc  :
import base64
from urllib.parse import urlencode

import requests
import urllib3

from External.cdncheck import CDNCheck
from Lib import api
from Lib.timeapi import TimeAPI
from Lib.xcache import Xcache
from WebDatabase.Interface.dataset import DataSet
from WebDatabase.documents import IPDomainDocument, PortDocument, DNSRecordDocument, CDNDocument, CertDocument, ComponentDocument, HttpBaseDocument, \
    LocationDocument, ServiceDocument

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FOFAClient(object):
    def __init__(self):
        self.email = None
        self.key = None
        self.base_url = "https://fofa.info"
        self.search_api_url = "/api/v1/search/all"
        self.login_api_url = "/api/v1/info/my"
        self.fields = ["ip", "port", "protocol", "country_name", "as_organization"]
        self.fields_normal = ["ip", "port", "protocol", "country", "country_name", "region", "city", "longitude",
                              "latitude", "as_number", "as_organization", "host", "domain", "os", "server", "icp",
                              "title", "jarm", "header", "banner", "cert", "base_protocol", "link", "certs_issuer_org",
                              "certs_issuer_cn", "certs_subject_org", "certs_subject_cn"]
        self.fields_pro = ["product", "product_category", "version", "lastupdatetime", "cname", ]
        self.fields_business = ["icon_hash", "certs_valid", "cname_domain", "body"]

    def set_email_and_key(self, email, key):
        self.email = email
        self.key = key

    def init_conf_from_cache(self):
        conf = Xcache.get_fofa_conf()
        if conf.get("alive") is not True:
            return False
        else:
            self.email = conf.get("email")
            self.key = conf.get("key")
            return True

    def get_userinfo(self):
        api_full_url = "%s%s" % (self.base_url, self.login_api_url)
        param = {"email": self.email, "key": self.key}
        res = self.__http_get(api_full_url, param)
        return res

    def is_alive(self):
        # {"email":"XXX@XXX.org","username":"XXX","fcoin":0,"isvip":true,"vip_level":2,"is_verified":false,"avatar":"https://nosec.org/missing.jpg","message":0,"fofacli_ver":"3.10.4","fofa_server":true}
        userdata = self.get_userinfo()
        if userdata.get("isvip"):
            return True
        else:
            return False

    def get_data(self, query_str, page, size):
        errmsg, res = self.get_json_data(query_str, page, size)
        if errmsg is not None:
            return False, errmsg

        format_results = []
        i = 0
        for result in res:
            result['index'] = i
            format_results.append(result)
            i += 1
        return True, format_results

    def get_json_data(self, query_str, page=1, size=0):
        max_num = Xcache.get_common_conf_by_key("max_record_num_for_one_search")
        if size != 0:
            max_num = size

        api_full_url = "%s%s" % (self.base_url, self.search_api_url)
        fields = []
        fields.extend(self.fields_normal)
        fields.extend(self.fields_pro)
        # fields.extend(self.fields_business)
        param = {"qbase64": base64.b64encode(query_str.encode(encoding="UTF-8", errors="ignore")), "email": self.email,
                 "key": self.key,
                 "page": page,
                 "size": max_num,
                 "fields": ",".join(fields)}

        # debug hook start
        # if Xcache.get_sample_data("FOFA_DOMAIN", query_str) is None:
        #     data = self.__http_get(api_full_url, param)
        #     Xcache.set_sample_data("FOFA_DOMAIN", query_str, data)
        # else:
        #     data = Xcache.get_sample_data("FOFA_DOMAIN", query_str)
        # debug hook end

        data = self.__http_get(api_full_url, param)

        format_results = []
        if data.get("error") is False:
            results = data.get("results")
            for result in results:
                format_result = {}
                for field, value in zip(fields, result):
                    format_result[field] = value
                format_results.append(format_result)
            return None, format_results
        else:
            return data.get("errmsg"), None

    def get_dataset(self, items) -> DataSet:
        dataset = DataSet()
        for item in items:
            format = '%Y-%m-%d %H:%M:%S'
            update_time = TimeAPI.str_to_timestamp(item.get("lastupdatetime"), format)

            ip = item.get("ip")
            url = item.get("host")
            urlparse_result = api.urlparse(url)
            domain = urlparse_result.hostname

            port = int(item.get("port"))
            service_name = item.get("protocol")

            asname = item.get("as_organization")
            source = "FOFA"

            a = None
            if ip and domain:
                a = [ip]
            cname = item.get('cname')
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
                dnsrecord_obj.value = [cname]
                dnsrecord_obj.source = source
                dnsrecord_obj.update_time = update_time
                dataset.dnsrecordList.append(dnsrecord_obj)

            if cname:
                cdn_record = CDNCheck.check(cname)
                if cdn_record:
                    cdn_obj = CDNDocument()
                    cdn_obj.ipdomain = domain
                    cdn_obj.flag = True
                    cdn_obj.domain = cdn_record.get("domain")
                    cdn_obj.name = cdn_record.get("name")
                    cdn_obj.link = cdn_record.get("link")
                    cdn_obj.source = source
                    cdn_obj.update_time = update_time
                    dataset.cdnList.append(cdn_obj)
                else:
                    cdn_obj = CDNDocument()
                    cdn_obj.ipdomain = domain
                    cdn_obj.flag = False
                    cdn_obj.domain = None
                    cdn_obj.name = None
                    cdn_obj.link = None
                    cdn_obj.source = source
                    cdn_obj.update_time = update_time
                    dataset.cdnList.append(cdn_obj)
            else:
                cdn_obj = CDNDocument()
                cdn_obj.ipdomain = domain
                cdn_obj.flag = False
                cdn_obj.domain = None
                cdn_obj.name = None
                cdn_obj.link = None
                cdn_obj.source = source
                cdn_obj.update_time = update_time
                dataset.cdnList.append(cdn_obj)

            if domain is None:
                ipdomain = ip
            else:
                ipdomain = domain

            ipdomain_object = IPDomainDocument()
            ipdomain_object.ipdomain = ipdomain
            ipdomain_object.source = source
            ipdomain_object.update_time = update_time
            dataset.ipdomainList.append(ipdomain_object)

            isp = None
            location_obj = LocationDocument()
            location_obj.ipdomain = ipdomain
            location_obj.isp = isp
            location_obj.asname = asname

            location_obj.scene_cn = None
            location_obj.scene_en = None

            location_obj.country_cn = item.get("country_name")
            location_obj.country_en = item.get("country_name")
            location_obj.province_cn = item.get("region")
            location_obj.province_en = item.get("region")
            location_obj.city_cn = item.get("city")
            location_obj.city_en = item.get("city")

            location_obj.source = source
            location_obj.update_time = update_time
            dataset.locationList.append(location_obj)

            port_object = PortDocument()
            port_object.ipdomain = ipdomain
            port_object.port = port
            port_object.alive = True
            port_object.source = source
            port_object.update_time = update_time
            dataset.portList.append(port_object)

            transport = item.get("base_protocol")
            version = item.get("version")

            service_obj = ServiceDocument()
            service_obj.ipdomain = ipdomain
            service_obj.port = port
            service_obj.service = service_name
            service_obj.version = version
            service_obj.transport = transport
            service_obj.source = source
            service_obj.update_time = update_time
            dataset.serviceList.append(service_obj)

            # ComponentModel
            for product_name, product_type in zip(item.get("product").split(","),
                                                  item.get("product_category").split(",")):
                component_object: ComponentDocument = ComponentDocument()
                component_object.ipdomain = ipdomain
                component_object.port = port
                component_object.product_name = product_name
                component_object.product_type = [product_type]
                component_object.source = source
                component_object.update_time = update_time
                dataset.componentList.append(component_object)

            # Cert
            # TODO 存储cert配置信息
            cert_config = {'certs_issuer_org': item.get("certs_issuer_org"),
                           'certs_issuer_cn': item.get("certs_issuer_cn"),
                           'certs_subject_org': item.get("certs_subject_org"),
                           'certs_subject_cn': item.get("certs_subject_cn"), }
            if item.get("cert"):
                jarm_hash = item.get("jarm")
                cert = item.get("cert")

                cert_object = CertDocument()
                cert_object.ipdomain = ipdomain
                cert_object.port = port
                cert_object.cert = cert
                cert_object.jarm = jarm_hash
                cert_object.source = source
                cert_object.update_time = update_time
                cert_object.data = cert_config
                dataset.certList.append(cert_object)

            # http
            if service_name.startswith("http"):
                # HttpBaseModel
                httpbase_object = HttpBaseDocument()
                httpbase_object.ipdomain = ipdomain
                httpbase_object.port = port
                httpbase_object.title = item.get("title")
                httpbase_object.header = item.get("header")
                httpbase_object.source = source
                httpbase_object.update_time = update_time
                dataset.httpbaseList.append(httpbase_object)

            # DomainICPModel
            # if item.get("icp"):
            #     domain_icp = item.get("domain")
        return dataset

    @staticmethod
    def __http_get(url, param):
        param = urlencode(param)
        url = "%s?%s" % (url, param)

        try:
            r = requests.get(url=url, verify=False, headers={'Connection': 'close'})
            return r.json()
        except Exception as e:
            raise e
