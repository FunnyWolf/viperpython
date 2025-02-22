# -*- coding: utf-8 -*-
# @File  : fofaclient.py
# @Date  : 2021/2/25
# @Desc  :

import base64
import datetime
import time

import requests
import urllib3

from Lib.timeapi import TimeAPI
from Lib.xcache import Xcache
from WebDatabase.Interface.dataset import DataSet
from WebDatabase.documents import IPDomainDocument, PortDocument, DNSRecordDocument, ComponentDocument, LocationDocument, ServiceDocument, HttpBaseDocument

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Hunter(object):
    def __init__(self):
        self.key = None
        self.base_url = "https://hunter.qianxin.com"
        self.search_api_url = "/openApi/search"

    def set_key(self, key):
        self.key = key

    def init_conf_from_cache(self):
        conf = Xcache.get_hunter_conf()
        if conf.get("alive") is not True:
            return False
        else:
            self.key = conf.get("key")
            return True

    def check_alive(self):
        res = self.get_data('ip="10.10.10.10"', page=1, page_size=1)
        if res.get("code") == 200:
            return True
        else:
            return False

    def get_json_data(self, query_str):
        if Xcache.get_sample_data("HUNTER_DOMAIN", query_str) is None:
            msg, res = self.get_all_data(query_str)
            Xcache.set_sample_data("HUNTER_DOMAIN", query_str, res)
        else:
            res = Xcache.get_sample_data("HUNTER_DOMAIN", query_str)
            msg = "success"
        # msg, res = self.get_all_data(query_str, size)
        return msg, res

    def get_all_data(self, query_str):
        max_num = Xcache.get_common_conf_by_key("max_record_num_for_one_search")
        result = []
        page = 1
        res = self.get_data(query_str, page, 100)
        if res.get("code") == 200:
            arr = res.get("data").get("arr")
            if arr is None:
                return res.get("message"), []

            # print(f'{res.get("data").get("consume_quota")} {res.get("data").get("rest_quota")}')
            total = res.get("data").get("total")
            result.extend(arr)
        else:
            return res.get("message"), None

        if total <= 100:
            return res.get("message"), result

        while True:
            page += 1
            res = self.get_data(query_str, page, 100)
            time.sleep(3)
            if res.get("code") == 200:
                arr = res.get("data").get("arr")
                if arr is None:
                    break
                result.extend(arr)

                if len(result) >= max_num:
                    break
                if len(result) >= total:
                    break
            elif res.get("code") == 429:
                time.sleep(5)
                page -= 1
                continue
            else:
                break
        return res.get("message"), result

    def get_data(self, query_str, page, page_size):
        today = datetime.date.today()
        year_ago = today.replace(year=today.year - 1)

        api_full_url = f"{self.base_url}{self.search_api_url}"

        query_str = base64.urlsafe_b64encode(query_str.encode("utf-8")).decode("utf-8")

        data = {
            'api-key': self.key,
            "search": query_str,
            "page": page,
            "page_size": page_size,
            "is_web": 3,
            "start_time": str(year_ago),
            "end_time": str(today)
        }

        res = self.__http_get(api_full_url, data)
        return res

    def __http_get(self, url, params):
        try:
            headers = {
                "Content-Type": "application/json",
                'Connection': 'close'
            }
            r = requests.get(url=url, params=params, verify=False, headers=headers)
            return r.json()
        except Exception as e:
            return None

    def get_dataset(self, items) -> DataSet:
        dataset = DataSet()
        source = 'Hunter'

        for item in items:
            update_time = TimeAPI.str_to_timestamp(item.get("updated_at"), "%Y-%m-%d")

            ip = item.get("ip")
            domain = item.get("domain")

            port = item.get("port")

            response = item.get("banner")

            service_name = item.get("protocol")

            transport = item.get("base_protocol")

            isp = item.get("isp")
            asname = item.get("as_org")

            components = item.get("component")

            if domain is None:
                ipdomain = ip
            else:
                ipdomain = domain

                # 手动组合dns记录
                dnsrecord_obj: DNSRecordDocument = DNSRecordDocument()
                dnsrecord_obj.ipdomain = domain
                dnsrecord_obj.type = "A"
                dnsrecord_obj.value = [ip]
                dnsrecord_obj.source = source
                dnsrecord_obj.update_time = update_time
                dataset.dnsrecordList.append(dnsrecord_obj)

            ipdomain_object = IPDomainDocument()
            ipdomain_object.ipdomain = ipdomain
            ipdomain_object.source = source
            ipdomain_object.update_time = update_time
            dataset.ipdomainList.append(ipdomain_object)

            port_object = PortDocument()
            port_object.ipdomain = ipdomain
            port_object.port = port
            port_object.alive = True
            port_object.source = source
            port_object.update_time = update_time
            dataset.portList.append(port_object)

            location_obj = LocationDocument()
            location_obj.ipdomain = ipdomain
            location_obj.isp = isp
            location_obj.asname = asname

            location_obj.scene_cn = None
            location_obj.scene_en = None

            location_obj.country_cn = item.get("conuntry")
            location_obj.country_en = item.get("conuntry")
            location_obj.province_cn = item.get("province")
            location_obj.province_en = item.get("province")
            location_obj.city_cn = item.get("city")
            location_obj.city_en = item.get("city")

            location_obj.source = source
            location_obj.update_time = update_time
            dataset.locationList.append(location_obj)

            service_obj = ServiceDocument()
            service_obj.ipdomain = ipdomain
            service_obj.port = port
            service_obj.service = service_name
            service_obj.transport = transport
            service_obj.response = response
            service_obj.source = source
            service_obj.update_time = update_time
            dataset.serviceList.append(service_obj)

            # ComponentModel
            if components:
                components = item.get("component")
                for component in components:
                    product_name = component.get("name")
                    product_version = component.get("version")

                    component_object: ComponentDocument = ComponentDocument()
                    component_object.ipdomain = ipdomain
                    component_object.port = port
                    component_object.product_name = product_name
                    component_object.product_version = product_version

                    component_object.data = component
                    component_object.source = source
                    component_object.update_time = update_time
                    dataset.componentList.append(component_object)

            # http
            if service_name.startswith("http"):
                httpbase_object = HttpBaseDocument()
                httpbase_object.ipdomain = ipdomain
                httpbase_object.port = port
                httpbase_object.title = item.get("web_title")
                httpbase_object.status_code = item.get("status_code")
                httpbase_object.source = source
                httpbase_object.update_time = update_time
                dataset.httpbaseList.append(httpbase_object)

                # DomainICPModel
                # if item.get("company"):
                #     domain_icp = item.get("domain")
                #     unit = item.get("company")
                #     DomainICP.update_or_create(ipdomain=domain_icp,
                #                                license=item.get("number"),
                #                                unit=unit, webbase_dict=webbase_dict)
        return dataset
