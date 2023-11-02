# -*- coding: utf-8 -*-
# @File  : fofaclient.py
# @Date  : 2021/2/25
# @Desc  :

import base64

import requests
import urllib3

from Lib.configs import DEFAULT_PROJECT_ID
from Lib.log import logger
from Lib.timeapi import TimeAPI
from Lib.xcache import Xcache
from WebDatabase.Handle.cdn import CDN
from WebDatabase.Handle.cert import Cert
from WebDatabase.Handle.component import Component
from WebDatabase.Handle.dnsrecord import DNSRecord
from WebDatabase.Handle.domainicp import DomainICP
from WebDatabase.Handle.httpbase import HttpBase
from WebDatabase.Handle.httpfavicon import HttpFavicon
from WebDatabase.Handle.ipdomain import IPDomain
from WebDatabase.Handle.location import Location
from WebDatabase.Handle.portservice import PortService
from WebDatabase.Handle.screenshot import Screenshot

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Quake:
    def __init__(self):
        self.key = None
        self.base_url = "https://quake.360.cn"
        self.search_api_url = "/api/v3/search/quake_service"
        # self.search_api_url = "/api/v3/scroll/quake_service"
        self.user_info_url = "/api/v3/user/info"
        self.fields = ["ip", "port", "protocol", "country_name", "as_organization"]
        self.headers = {
            "X-QuakeToken": self.key,
            "Content-Type": "application/json",
            'Connection': 'close'
        }

    def set_key(self, key):
        self.key = key

    def init_conf_from_cache(self):
        conf = Xcache.get_quake_conf()
        if conf.get("alive") is not True:
            return False
        else:
            self.key = conf.get("key")
            return True

    def get_userinfo(self):
        api_full_url = f"{self.base_url}{self.user_info_url}"

        res = self.__http_get(api_full_url)
        return res

    def check_alive(self):
        userdata = self.get_userinfo()
        if userdata is None:
            return False
        if userdata.get("message") == "Successful.":
            return True
        else:
            return False

    def get_data(self, query_str, page=1, size=100):
        msg, data = self.get_json_data(query_str, page, size)
        if data:
            format_results = []
            i = 0
            for onedict in data:
                one_line = {
                    "index": i,
                    "ip": onedict.get('ip'),
                    "port": onedict.get('port'),
                    "protocol": onedict.get('service').get('name'),
                    "country_name": onedict.get('location').get('country_cn'),
                    "as_organization": onedict.get('location').get('isp'),
                }
                format_results.append(one_line)
                i += 1
            return True, format_results
        else:
            return False, msg

    def get_json_data(self, query_str, page=1, size=1000):
        api_full_url = f"{self.base_url}{self.search_api_url}"
        data = {
            "query": query_str,
            "start": (page - 1) * size,
            "size": size,
        }

        # debug hook start
        if Xcache.get_sample_data("QUAKE_DOMAIN", query_str) is None:
            res = self.__http_post(api_full_url, data)
            Xcache.set_sample_data("QUAKE_DOMAIN", query_str, res)
        else:
            res = Xcache.get_sample_data("QUAKE_DOMAIN", query_str)
        # debug hook end
        # res = self.__http_post(api_full_url, data)

        if res.get("message") == 'Successful.':
            # 处理meta部分,确保获取到所有数据
            return res.get("message"), res.get("data")
        else:
            return res.get("message"), None

    def query_by_domain(self, domain, page=1, size=1000):
        query_str = f"domain:\"{domain}\""
        return self.get_json_data(query_str, page, size)

    def __http_post(self, url, data):
        try:
            headers = {
                "X-QuakeToken": self.key,
                "Content-Type": "application/json",
                'Connection': 'close'
            }
            r = requests.post(url=url, json=data, verify=False, headers=headers)
            return r.json()
        except Exception as e:
            return None

    def __http_get(self, url):
        try:
            headers = {
                "X-QuakeToken": self.key,
                "Content-Type": "application/json",
                'Connection': 'close'
            }
            r = requests.get(url=url, verify=False, headers=headers)
            return r.json()
        except Exception as e:
            return None

    @staticmethod
    def get_images_base64(url):
        if not url:
            return None
        try:
            response = requests.get(url)
            image_bytes = response.content
            image_base64 = base64.b64encode(image_bytes).decode('utf-8')
        except Exception as E:
            logger.exception(E)
            return None
        return image_base64

    @staticmethod
    def is_cdn_record(cname):
        if cname is None or len(cname) == 0:
            return False
        else:
            return True

    def store_query_result(self, items, project_id=DEFAULT_PROJECT_ID, source_key=None):
        source = "Quake"

        for item in items:
            update_time = TimeAPI.str_to_timestamp(item.get("time"), '%Y-%m-%dT%H:%M:%S.%fZ')

            ip = item.get("ip")
            domain = item.get("domain")

            port = item.get("port")

            service_config = item.get("service")
            dns_reocord = service_config.get("dns")

            service_name = service_config.get("name")

            location_config = item.get("location")
            isp = location_config.pop("isp")
            asname = location_config.pop("asname")

            components = item.get("components")
            images = item.get("images")

            webbase_dict = {
                'source': source,
                "source_key": source_key,
                # 'data': item,
                'update_time': update_time,
            }
            a = []
            cname = []

            # DNS 信息
            if domain is None:  # 只有IP
                pass
            else:
                if dns_reocord is None:  # 存在A记录,但是未添加到result中
                    a = [ip]
                else:
                    a = dns_reocord.get("a")
                    if a is None:
                        a = []
                    cname = dns_reocord.get("cname")
                    if cname is None:
                        cname = []
                # 存储dns
                DNSRecord.update_or_create(domain=domain, a=a, cname=cname, webbase_dict=webbase_dict)

                if Quake.is_cdn_record(cname):
                    # 只保存Domain信息
                    ip = None
                    cname = dns_reocord.get("cname")
                    a = dns_reocord.get("a")
                    CDN.update_or_create(domain=domain, port=port, cname=cname, a=a, webbase_dict=webbase_dict)

            for ipdomain in [ip, domain]:
                if ipdomain is None:
                    continue
                IPDomain.update_or_create(project_id=project_id,
                                          ipdomain=ipdomain,
                                          webbase_dict=webbase_dict)
                Location.update_or_create(ipdomain=ipdomain,
                                          isp=isp,
                                          asname=asname,
                                          geo_info=location_config,
                                          webbase_dict=webbase_dict
                                          )
                PortService.update_or_create(ipdomain=ipdomain, port=port,
                                             transport=item.get("transport"),
                                             service=service_name,
                                             version=service_config.get("version"),
                                             webbase_dict=webbase_dict
                                             )
                # HttpComponentModel
                if components:
                    components = item.get("components")
                    for component in components:
                        product_name = component.get("product_name_en")
                        product_version = component.get("version")
                        product_type = component.get("product_type")
                        product_catalog = component.get("product_catalog")
                        product_dict_values = component

                        Component.update_or_create(ipdomain=ipdomain,
                                                   port=port,
                                                   product_name=product_name,
                                                   product_version=product_version,
                                                   product_type=product_type,
                                                   product_catalog=product_catalog,
                                                   product_dict_values=product_dict_values,
                                                   webbase_dict=webbase_dict
                                                   )

                # HttpScreenshot
                if images:
                    for image in images:
                        image_base64 = Quake.get_images_base64(image.get("s3_url"))
                        Screenshot.update_or_create(ipdomain=ipdomain, port=port, content=image_base64,
                                                    webbase_dict=webbase_dict)

                if service_name.endswith("/ssl"):
                    # Cert
                    tls_jarm = service_config.get("tls-jarm")
                    if tls_jarm:
                        jarm_hash = tls_jarm.get("jarm_hash")
                    else:
                        jarm_hash = None

                    Cert.update_or_create(ipdomain=ipdomain, port=port,
                                          cert=service_config.get("cert"),
                                          jarm=jarm_hash,
                                          webbase_dict=webbase_dict
                                          )

                if service_name.startswith("http"):
                    http_config = service_config.get("http")
                    # HttpBaseModel
                    HttpBase.update_or_create(ipdomain=ipdomain, port=port,
                                              title=http_config.get("title"),
                                              status_code=http_config.get("status_code"),
                                              header=http_config.get("response_headers"),
                                              response=service_config.get("response"),
                                              body=http_config.get("body"),
                                              webbase_dict=webbase_dict
                                              )

                    # HttpFavicon
                    if http_config.get("favicon"):
                        favicon_config = http_config.get("favicon")
                        favicon_base64 = Quake.get_images_base64(favicon_config.get("s3_url"))
                        if favicon_base64:
                            favicon_hash = favicon_config.get("hash")
                            HttpFavicon.update_or_create(ipdomain=ipdomain, port=port, content=favicon_base64,
                                                         hash=favicon_hash, webbase_dict=webbase_dict)

                    # DomainICPModel
                    if http_config.get("icp"):
                        icp_config = http_config.get("icp")
                        domain_icp = icp_config.get("domain")
                        main_license = icp_config.get("main_licence")
                        unit = main_license.get("unit")
                        update_time_icp = TimeAPI.str_to_timestamp(icp_config.get("update_time"),
                                                                   format='%Y-%m-%dT%H:%M:%SZ')
                        webbase_dict_icp = {}
                        webbase_dict_icp.update(webbase_dict)
                        webbase_dict_icp["update_time"] = update_time_icp

                        IPDomain.update_or_create(project_id=project_id, ipdomain=domain_icp,
                                                  webbase_dict=webbase_dict)

                        DomainICP.update_or_create(ipdomain=domain_icp,
                                                   license=icp_config.get("licence"),
                                                   unit=unit, webbase_dict=webbase_dict_icp)
