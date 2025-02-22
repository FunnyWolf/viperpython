# -*- coding: utf-8 -*-
# @File  : fofaclient.py
# @Date  : 2021/2/25
# @Desc  :

import time

import requests
import urllib3

from External.cdncheck import CDNCheck
from Lib.customexception import CustomException
from Lib.file import File
from Lib.log import logger
from Lib.timeapi import TimeAPI
from Lib.xcache import Xcache
from WebDatabase.Interface.dataset import DataSet
from WebDatabase.documents import IPDomainDocument, PortDocument, DNSRecordDocument, CertDocument, ComponentDocument, CDNDocument, HttpFaviconDocument, \
    LocationDocument, ServiceDocument, HttpBaseDocument, ScreenshotDocument

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class QuakeSetting(object):
    def __init__(self):
        pass

    @staticmethod
    def list():
        quake_conf = Xcache.get_quake_conf()
        result = []
        for key in quake_conf:
            try:
                one_conf = QuakeSetting.get(key)
            except Exception as E:
                logger.exception(E)
                continue
            result.append(one_conf)
        return result

    @staticmethod
    def get(key):
        client = Quake()
        config = client.set_key(key)
        return config

    @staticmethod
    def add(key):
        client = Quake()
        one_settting_config = client.set_key(key)
        quake_conf = Xcache.get_quake_conf()
        quake_conf[key] = one_settting_config
        Xcache.set_quake_conf(quake_conf)
        return one_settting_config

    @staticmethod
    def get_available_key():
        quake_conf = Xcache.get_quake_conf()
        for key in quake_conf:
            try:
                one_conf = QuakeSetting.get(key)
            except Exception as E:
                logger.exception(E)
                continue
            month_remaining_credit = one_conf.get("month_remaining_credit")
            constant_credit = one_conf.get("constant_credit")
            if constant_credit + month_remaining_credit > 1:
                return one_conf
            else:
                continue
        else:
            raise CustomException("无可用的Quake API KEY", "No available Quake API KEY")

    @staticmethod
    def delete(key):
        quake_conf = Xcache.get_quake_conf()
        if quake_conf.get(key) is None:
            return False
        quake_conf.pop(key)
        Xcache.set_quake_conf(quake_conf)
        return True


class Quake(object):
    def __init__(self):
        self.key = None
        self.base_url = "https://quake.360.cn"
        self.search_api_url = "/api/v3/search/quake_service"
        self.scroll_api_url = "/api/v3/scroll/quake_service"
        self.user_info_url = "/api/v3/user/info"
        self.fields = ["ip", "port", "protocol", "country_name", "as_organization"]

        # self.max_size_one_page = 500  # vip is 1000 , normal is 500
        self.delay = 3
        self.pagination_id = None

        self.ban_status = None
        self.role_list = None
        self.free_query_api_count = 0
        self.month_remaining_credit = 0
        self.constant_credit = 0
        self.user_info = {}
        self.account_role = None

    @property
    def headers(self):
        return {
            "X-QuakeToken": self.key,
            "Content-Type": "application/json",
            'Connection': 'close'
        }

    def set_key(self, key):
        self.key = key
        self.user_info = self.get_user_info()
        self.role_list = self.user_info.get("role")
        self.ban_status = self.user_info.get("ban_status")
        self.constant_credit = self.user_info.get("constant_credit")
        self.month_remaining_credit = self.user_info.get("month_remaining_credit")
        self.free_query_api_count = self.user_info.get("free_query_api_count")
        baned = self.user_info.get('baned')
        if baned:
            raise CustomException("Quake Token 已被封禁", "Quake Token Banned")

        for one_role in self.role_list:
            fullname = one_role.get("fullname")
            if fullname == "实名认证":
                self.account_role = one_role.get("fullname")
            if fullname == "终身会员":
                self.account_role = one_role.get("fullname")

        if self.account_role is None:
            raise CustomException("Quake Token 未实名认证", "Quake Token not real name authentication")

        one_settting_config = {
            "key": key,
            "constant_credit": self.constant_credit,
            "month_remaining_credit": self.month_remaining_credit,
            "free_query_api_count": self.free_query_api_count,
            "ban_status": self.ban_status,
            "account_role": self.account_role,
        }
        return one_settting_config

    def get_user_info(self):
        api_full_url = f"{self.base_url}{self.user_info_url}"
        res = self.__http_get(api_full_url)
        data = res.get("data")
        return data

    def update_info(self):
        self.user_info = self.get_user_info()
        if not self.user_info:
            return False

        self.role_list = self.user_info.get("role")
        self.ban_status = self.user_info.get("ban_status")
        self.constant_credit = self.user_info.get("constant_credit")
        self.month_remaining_credit = self.user_info.get("month_remaining_credit")
        self.free_query_api_count = self.user_info.get("free_query_api_count")
        return True

    def init_conf_from_cache(self):
        quake_config = QuakeSetting.get_available_key()
        self.set_key(quake_config.get("key"))

    def get_data(self, query_str, page=1, size=100):
        res = self.get_json_data(query_str, page, size)
        data = res.get("data")
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
            return False, None

    def get_json_data(self, query_str, page=1, size=100):
        api_full_url = f"{self.base_url}{self.search_api_url}"
        data = {
            "query": query_str,
            "start": (page - 1) * size,
            "size": size,
        }
        res = self.__http_post(api_full_url, data)
        return res

    def _get_scroll_data(self, query_str):

        max_num = Xcache.get_common_conf_by_key("max_record_num_for_one_search")

        pagination_id = None
        result = []
        api_full_url = f"{self.base_url}{self.scroll_api_url}"
        while True:
            # user info
            flag = self.update_info()
            if not flag:
                time.sleep(self.delay)
                continue

            # 360quake will check credit left for the account so max_num need to smaller than credit left
            max_size = min(max_num, self.month_remaining_credit + self.constant_credit - 1)
            if max_size < 1:
                self.init_conf_from_cache()
                continue

            # search
            if pagination_id is None:
                data = {
                    "query": query_str,
                    "size": max_size,
                    "latest": True,
                    "ignore_cache": True,
                }
            else:
                data = {
                    "query": query_str,
                    "size": max_size,
                    "latest": True,
                    "ignore_cache": True,
                    "pagination_id": pagination_id,
                }

            res = self.__http_post(api_full_url, data)
            code = res.get("code")
            message = res.get("message")
            meta = res.get("meta")
            total = meta.get("total")
            data = res.get("data")
            if code == 0:
                logger.info(f'Quake Result Count: {len(res.get("data"))}')
                if pagination_id is None:  # first request
                    pagination_id = meta.get("pagination_id")
                    result.extend(data)
                    continue
                elif not data:  # last data
                    break
                else:
                    result.extend(data)
            elif code == "q3005":  # 请求过于频繁
                logger.warning(f'Quake Return Code: {code} {message}')
                time.sleep(self.delay)
                continue
            elif code == "q2001":
                # q2001 用户当前积分不足以完成本次查询操作。-Quake Return Code MSG: q2001 用户当前积分不足以完成本次查询操作。
                logger.warning(f'Quake Return Code: {code} {message}')
                self.init_conf_from_cache()
                continue
            else:
                raise CustomException(f'Quake Return Code MSG: {code} {message}', f'Quake Return Code MSG: {code} {message}')
        # 返回结果
        return result

    def search_by_query_str(self, query_str, dataset: DataSet, company_name=None):
        # TODO : debug code
        if Xcache.get_sample_data("QUAKE_DOMAIN", query_str) is None:
            data = self._get_scroll_data(query_str)
            Xcache.set_sample_data("QUAKE_DOMAIN", query_str, data)
        else:
            data = Xcache.get_sample_data("QUAKE_DOMAIN", query_str)

        # data = self._get_scroll_data(query_str)
        self.store_data_to_dateset(data, dataset, company_name)
        return len(data)

    @staticmethod
    def store_data_to_dateset(items, dataset, company_name) -> DataSet:
        for item in items:
            if "." in item.get("time"):
                format = '%Y-%m-%dT%H:%M:%S.%fZ'
            else:
                format = '%Y-%m-%dT%H:%M:%SZ'
            update_time = TimeAPI.str_to_timestamp(item.get("time"), format)

            ip = item.get("ip")
            domain = item.get("domain")

            port = item.get("port")

            service_data = item.get("service")
            if service_data is None:
                service_data = {}

            response = service_data.get("response")
            response_hash = service_data.get("response_hash")
            dns_reocord = service_data.get("dns")

            service_name = service_data.get("name")
            if service_name == "http/ssl":
                service_name = "https"

            location_config = item.get("location")
            if location_config is None:
                location_config = {}
            isp = location_config.get("isp")
            asname = location_config.get("asname")

            components = item.get("components")
            images = item.get("images")
            source = '360Quake'

            # DNS 信息
            if dns_reocord:
                a = dns_reocord.get("a")
                cname = dns_reocord.get("cname")

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

                # CDN
                if cname:
                    for one_cname in cname:
                        cdn_record = CDNCheck.check(one_cname)
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

            if domain is None or domain == "":
                ipdomain = ip
            else:
                ipdomain = domain
            ipdomain_object = IPDomainDocument()
            ipdomain_object.project_id = dataset.project_id  # IPDomain在此更新project_id
            ipdomain_object.company_name = company_name
            ipdomain_object.ipdomain = ipdomain
            ipdomain_object.source = source
            ipdomain_object.update_time = update_time
            dataset.ipdomainList.append(ipdomain_object)

            location_obj = LocationDocument()
            location_obj.ipdomain = ipdomain
            location_obj.isp = isp
            location_obj.asname = asname

            location_obj.scene_cn = location_config.get("scene_cn")
            location_obj.scene_en = location_config.get("scene_en")

            location_obj.country_cn = location_config.get("country_cn")
            location_obj.country_en = location_config.get("country_en")
            location_obj.province_cn = location_config.get("province_cn")
            location_obj.province_en = location_config.get("province_en")
            location_obj.city_cn = location_config.get("city_cn")
            location_obj.city_en = location_config.get("city_en")

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

            service_obj = ServiceDocument()
            service_obj.ipdomain = ipdomain
            service_obj.port = port
            service_obj.service = service_name
            service_obj.version = service_data.get("version")
            service_obj.transport = item.get("transport")
            service_obj.response = response
            service_obj.response_hash = response_hash
            service_obj.source = source
            service_obj.update_time = update_time
            dataset.serviceList.append(service_obj)

            # ComponentModel
            if components:
                components = item.get("components")
                for component in components:
                    product_name = component.get("product_name_en")
                    product_version = component.get("version")
                    product_type = component.get("product_type")
                    product_catalog = component.get("product_catalog")

                    component_object: ComponentDocument = ComponentDocument()
                    component_object.ipdomain = ipdomain
                    component_object.port = port
                    component_object.product_name = product_name
                    component_object.product_version = product_version
                    component_object.product_type = product_type
                    component_object.product_catalog = product_catalog
                    component_object.data = component
                    component_object.source = source
                    component_object.update_time = update_time
                    dataset.componentList.append(component_object)

            # Screenshot
            if images:
                for image in images:
                    s3_url = image.get("s3_url")
                    if s3_url is None or s3_url == "":
                        continue
                    image_base64 = File.get_images_from_url(s3_url)
                    screenshot_object = ScreenshotDocument()
                    screenshot_object.ipdomain = ipdomain
                    screenshot_object.port = port
                    screenshot_object.content = image_base64
                    screenshot_object.source = source
                    screenshot_object.update_time = update_time
                    dataset.screenshotList.append(screenshot_object)

            # Cert
            try:
                if service_data.get("name").endswith("/ssl"):
                    tls_jarm = service_data.get("tls-jarm")
                    if tls_jarm:
                        jarm_hash = tls_jarm.get("jarm_hash")
                    else:
                        jarm_hash = None

                    parsed = service_data["tls"]["handshake_log"]["server_certificates"]["certificate"]["parsed"]
                    fingerprint_md5 = parsed.get("fingerprint_md5")

                    subject = parsed.get("subject")
                    if subject is None:
                        subject = {}
                    try:
                        subject["country"] = subject["country"][0]
                    except Exception:
                        subject["country"] = None

                    try:
                        subject["province"] = subject["province"][0]
                    except Exception:
                        subject["province"] = None

                    try:
                        subject["organization"] = subject["organization"][0]
                    except Exception:
                        subject["organization"] = None

                    try:
                        subject["locality"] = subject["locality"][0]
                    except Exception:
                        subject["locality"] = None

                    try:
                        subject["common_name"] = subject["common_name"][0]
                    except Exception:
                        subject["common_name"] = None

                    subject_dn = parsed.get("subject_dn")

                    extensions = parsed.get("extensions")
                    if extensions is None:
                        extensions = {}

                    subject_alt_name = extensions.get("subject_alt_name")
                    dns_names = subject_alt_name.get("dns_names")
                    # names = parsed.get("names")
                    # issuer = parsed.get("issuer")

                    cert_doc = CertDocument()
                    cert_doc.ipdomain = ipdomain
                    cert_doc.port = port
                    cert_doc.fingerprint_md5 = fingerprint_md5
                    cert_doc.cert = service_data.get("cert")
                    cert_doc.jarm = jarm_hash
                    cert_doc.subject = subject
                    cert_doc.subject_dn = subject_dn
                    cert_doc.dns_names = dns_names

                    cert_doc.source = source
                    # cert_doc.data = parsed
                    cert_doc.update_time = update_time
                    dataset.certList.append(cert_doc)
            except Exception as E:
                logger.exception(E)

            # http
            try:
                if service_name.startswith("http"):
                    http_config = service_data.get("http")

                    httpbase_object = HttpBaseDocument()
                    httpbase_object.ipdomain = ipdomain
                    httpbase_object.port = port
                    httpbase_object.title = http_config.get("title")
                    httpbase_object.status_code = http_config.get("status_code")
                    httpbase_object.header = http_config.get("response_headers")
                    httpbase_object.body = http_config.get("body")
                    httpbase_object.source = source
                    httpbase_object.update_time = update_time
                    dataset.httpbaseList.append(httpbase_object)

                    # HttpFavicon
                    if http_config.get("favicon"):
                        favicon_config = http_config.get("favicon")
                        favicon_base64 = File.get_images_from_url(favicon_config.get("location"))
                        if favicon_base64:
                            favicon_hash = favicon_config.get("hash")

                            httpfavicon_object = HttpFaviconDocument()
                            httpfavicon_object.ipdomain = ipdomain
                            httpfavicon_object.port = port
                            httpfavicon_object.content = favicon_base64
                            httpfavicon_object.hash = favicon_hash
                            httpfavicon_object.source = source
                            httpfavicon_object.update_time = update_time
                            dataset.httpfaviconList.append(httpfavicon_object)

                    # companyicp
                    # if http_config.get("icp"):
                    #     icp_config = http_config.get("icp")
                    #     domain_icp = icp_config.get("domain")
                    #     main_license = icp_config.get("main_licence")
                    #     unit = main_license.get("unit")
                    #     license = icp_config.get("licence")
                    #     update_time_icp = TimeAPI.str_to_timestamp(icp_config.get("update_time"),
                    #                                                format='%Y-%m-%dT%H:%M:%SZ')
                    #
                    #     companybaseinfo_object = CompanyBaseInfoObject()
                    #     companybaseinfo_object.titleName = unit
                    #     dataset.companyBaseInfoList.append(companybaseinfo_object)
                    #
                    #     companyicp_object = CompanyICPObject()
                    #     companyicp_object.domain = domain_icp
                    #     companyicp_object.icpNo = license
                    #     companyicp_object.source = source
                    #     companyicp_object.update_time = update_time_icp
                    #     dataset.companyICPList.append(companyicp_object)
            except Exception as E:
                logger.exception(E)

        return dataset

    def __http_post(self, url, data):
        headers = {
            "X-QuakeToken": self.key,
            "Content-Type": "application/json",
            'Connection': 'close'
        }
        r = requests.post(url=url, json=data, verify=False, headers=headers)
        return r.json()

    def __http_get(self, url):
        headers = {
            "X-QuakeToken": self.key,
            "Content-Type": "application/json",
            'Connection': 'close'
        }
        r = requests.get(url=url, verify=False, headers=headers)
        if r.status_code == 401:
            raise CustomException(msg_zh="Quake Token 不正确", msg_en="Quake Token Error")
        return r.json()
