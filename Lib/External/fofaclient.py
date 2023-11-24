# -*- coding: utf-8 -*-
# @File  : fofaclient.py
# @Date  : 2021/2/25
# @Desc  :
import json
from urllib.parse import urlencode

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import base64

import requests

from Lib.configs import DEFAULT_PROJECT_ID
from Lib.timeapi import TimeAPI
from Lib.xcache import Xcache
from WebDatabase.Handle.cdn import CDN
from WebDatabase.Handle.cert import Cert
from WebDatabase.Handle.component import Component
from WebDatabase.Handle.dnsrecord import DNSRecord
from WebDatabase.Handle.domainicp import DomainICP
from WebDatabase.Handle.httpbase import HttpBase
from WebDatabase.Handle.ipdomain import IPDomain
from WebDatabase.Handle.location import Location
from WebDatabase.Handle.portservice import PortService


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
        return json.loads(res)

    def is_alive(self):
        # {"email":"XXX@XXX.org","username":"XXX","fcoin":0,"isvip":true,"vip_level":2,"is_verified":false,"avatar":"https://nosec.org/missing.jpg","message":0,"fofacli_ver":"3.10.4","fofa_server":true}
        userdata = self.get_userinfo()
        if userdata.get("email") == self.email:
            return True
        else:
            return False

    def get_data(self, query_str, page=1, size=100):
        res = self.get_json_data(query_str, page, size)
        data = json.loads(res)
        format_results = []
        if data.get("error") is False:
            results = data.get("results")
            i = 0
            for result in results:
                format_result = {"index": i}
                for field, value in zip(self.fields, result):
                    format_result[field] = value
                format_results.append(format_result)
                i += 1
            return True, format_results
        else:
            return False, data.get("errmsg")

    def get_json_data(self, query_str, page=1, size=1000):
        api_full_url = "%s%s" % (self.base_url, self.search_api_url)
        fields = []
        fields.extend(self.fields_normal)
        fields.extend(self.fields_pro)
        # fields.extend(self.fields_business)
        param = {"qbase64": base64.b64encode(query_str.encode(encoding="UTF-8", errors="ignore")), "email": self.email,
                 "key": self.key,
                 "page": page,
                 "size": size,
                 "fields": ",".join(fields)}

        # debug hook start
        if Xcache.get_sample_data("FOFA_DOMAIN", query_str) is None:
            data = self.__http_get(api_full_url, param)
            Xcache.set_sample_data("FOFA_DOMAIN", query_str, data)
        else:
            data = Xcache.get_sample_data("FOFA_DOMAIN", query_str)
        # debug hook end

        # data = self.__http_get(api_full_url, param)

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

    @staticmethod
    def __http_get(url, param):
        param = urlencode(param)
        url = "%s?%s" % (url, param)

        try:
            r = requests.get(url=url, verify=False, headers={'Connection': 'close'})
            return r.json()
        except Exception as e:
            raise e

    @staticmethod
    def store_query_result(items, project_id=DEFAULT_PROJECT_ID, source={}):
        for item in items:
            format = '%Y-%m-%d %H:%M:%S'
            update_time = TimeAPI.str_to_timestamp(item.get("lastupdatetime"), format)

            ip = item.get("ip")
            host = item.get("host")
            if host.startswith("https://"):
                domain = host[8:]
            elif host.startswith("http://"):
                domain = host[7:]
            else:
                domain = None

            port = int(item.get("port"))
            service_name = item.get("protocol")
            if service_name == "https":
                service_name = "http/ssl"

            asname = item.get("as_organization")

            webbase_dict = {
                'source': source,
                'update_time': update_time,
                # 'data': item,
            }
            a = None
            if ip and domain:
                a = [ip]
            cname = item.get('cname')
            if a:
                DNSRecord.update_or_create(domain=domain, type="A", value=a, webbase_dict=webbase_dict)

            if cname:
                DNSRecord.update_or_create(domain=domain, type="CNAME", value=[cname], webbase_dict=webbase_dict)
                CDN.update_or_create(domain=domain, flag=True, webbase_dict=webbase_dict)
            else:
                CDN.update_or_create(domain=domain, flag=False, webbase_dict=webbase_dict)

            if domain is None:
                ipdomain = ip
            else:
                ipdomain = domain

            IPDomain.update_or_create(project_id=project_id,
                                      ipdomain=ipdomain,
                                      webbase_dict=webbase_dict)

            isp = None
            geo_info = {'country_cn': item.get("country_name"), 'province_cn': item.get("region"),
                        'city_cn': item.get("city"), }
            Location.update_or_create(ipdomain=ipdomain,
                                      isp=isp,
                                      asname=asname,
                                      geo_info=geo_info,
                                      webbase_dict=webbase_dict)
            response = None
            response_hash = None
            PortService.update_or_create(ipdomain=ipdomain, port=port,
                                         response=response,
                                         response_hash=response_hash,
                                         transport=item.get("base_protocol"),
                                         service=service_name,
                                         version=item.get("version"),
                                         webbase_dict=webbase_dict)

            # ComponentModel
            for product_name, product_type in zip(item.get("product").split(","),
                                                  item.get("product_category").split(",")):
                product_version = None
                product_catalog = []
                product_dict_values = {}

                Component.update_or_create(ipdomain=ipdomain,
                                           port=port,
                                           product_name=product_name,
                                           product_version=product_version,
                                           product_type=[product_type],
                                           product_catalog=product_catalog,
                                           product_dict_values=product_dict_values,
                                           webbase_dict=webbase_dict
                                           )

            # Cert
            # TODO 存储cert配置信息
            cert_config = {'certs_issuer_org': item.get("certs_issuer_org"),
                           'certs_issuer_cn': item.get("certs_issuer_cn"),
                           'certs_subject_org': item.get("certs_subject_org"),
                           'certs_subject_cn': item.get("certs_subject_cn"), }
            if item.get("cert"):
                jarm_hash = item.get("jarm")
                cert = item.get("cert")
                Cert.update_or_create(ipdomain=ipdomain, port=port,
                                      cert=cert,
                                      jarm=jarm_hash,
                                      webbase_dict=webbase_dict
                                      )

            # http
            if service_name.startswith("http"):
                # HttpBaseModel
                HttpBase.update_or_create(ipdomain=ipdomain, port=port,
                                          title=item.get("title"),
                                          status_code=0,
                                          header=item.get("header"),
                                          body=None,
                                          webbase_dict=webbase_dict
                                          )

            # DomainICPModel
            if item.get("icp"):
                domain_icp = item.get("domain")

                IPDomain.update_or_create(project_id=project_id, ipdomain=domain_icp,
                                          webbase_dict=webbase_dict)

                DomainICP.update_or_create(ipdomain=domain_icp,
                                           license=item.get("icp"),
                                           unit=None, webbase_dict=webbase_dict)
