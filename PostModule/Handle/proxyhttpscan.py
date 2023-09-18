# -*- coding: utf-8 -*-
# @File  : postmoduleauto.py
# @Date  : 2021/4/30
# @Desc  :
import importlib
import json
import uuid

import requests

from Lib.api import data_return, is_json
from Lib.configs import CODE_MSG_ZH, CODE_MSG_EN, ProxyHttpScan_MSG_ZH, \
    ProxyHttpScan_MSG_EN
from Lib.log import logger
from Lib.xcache import Xcache


class ProxyRequest(object):
    def __init__(self, request):
        # proxy request参数
        self.content = request.get("content")
        self.cookies = request.get("cookies")
        self.headers = request.get("headers")
        self.host = request.get("host")
        self.host_header = request.get("host_header")
        self.http_version = request.get("http_version")
        self.method = request.get("method")
        self.multipart_form = request.get("multipart_form")
        self.path = request.get("path")
        self.path_components = request.get("path_components")
        self.port = request.get("port")
        self.pretty_host = request.get("pretty_host")
        self.pretty_url = request.get("pretty_url")
        self.query = request.get("query")
        self.raw_content = request.get("raw_content")
        self.scheme = request.get("scheme")
        self.stream = request.get("stream")
        self.text = request.get("text")
        self.timestamp_end = request.get("timestamp_end")
        self.timestamp_start = request.get("timestamp_start")
        self.url = request.get("url")
        self.urlencoded_form = request.get("urlencoded_form")

        # requests参数
        self.log = False
        self.timeout = 3.0

    def copy(self):
        cls = self.__class__
        result = cls.__new__(cls)
        result.__dict__.update(self.__dict__)
        return result

    def send(self):
        if self.method == "GET":

            try:
                new_path = "/".join(self.path_components)
                url = f"{self.scheme}://{self.host_header}/{new_path}"
                result = requests.get(url,
                                      headers=self.headers,
                                      params=self.query,
                                      timeout=self.timeout)

                if self.log:
                    logger.warning(f"{self.method} URL:{url}")
                    logger.warning(f"HEADERS:{self.headers}")
                    logger.warning(f"QUERY:{self.query}")
                    logger.warning(f"RESULT:{result.status_code}  {result.text}")

                return result

            except requests.ReadTimeout as _:
                logger.warning(f"{self.method} URL:{self.pretty_url}")
                logger.warning(f"HEADERS:{self.headers}")
                logger.warning(f"DATA:{self.urlencoded_form}")
                logger.warning(f"socket.timeout")

            except Exception as E:
                logger.exception(E)

        elif self.method == "POST":
            if self.urlencoded_form:

                try:
                    result = requests.post(self.pretty_url,
                                           headers=self.headers,
                                           data=self.urlencoded_form,
                                           timeout=self.timeout
                                           )

                    if self.log:
                        logger.warning(f"{self.method} URL:{self.pretty_url}")
                        logger.warning(f"HEADERS:{self.headers}")
                        logger.warning(f"DATA:{self.urlencoded_form}")
                        logger.warning(f"RESULT:{result.status_code}  {result.text}")
                    return result
                except requests.ReadTimeout as _:
                    logger.warning(f"{self.method} URL:{self.pretty_url}")
                    logger.warning(f"HEADERS:{self.headers}")
                    logger.warning(f"DATA:{self.urlencoded_form}")
                    logger.warning(f"requests.ReadTimeout")
                except Exception as E:
                    logger.exception(E)

            else:
                if is_json(self.text):

                    try:
                        result = requests.post(self.pretty_url,
                                               headers=self.headers,
                                               json=json.loads(self.text),
                                               timeout=self.timeout)

                        if self.log:
                            logger.warning(f"{self.method} URL:{self.pretty_url}")
                            logger.warning(f"HEADERS:{self.headers}")
                            logger.warning(f"JSON:{json.loads(self.text)}")
                            logger.warning(f"RESULT:{result.status_code}  {result.text}")

                        return result
                    except requests.ReadTimeout as _:
                        logger.warning(f"{self.method} URL:{self.pretty_url}")
                        logger.warning(f"HEADERS:{self.headers}")
                        logger.warning(f"DATA:{self.urlencoded_form}")
                        logger.warning(f"socket.timeout")
                    except Exception as E:
                        logger.exception(E)


class ProxyResponse(object):
    def __init__(self, response):
        self.content = response.get("content")
        self.cookies = response.get("cookies")
        self.headers = response.get("headers")
        self.http_version = response.get("http_version")
        self.raw_content = response.get("raw_content")
        self.status_code = response.get("status_code")
        self.text = response.get("text")
        self.timestamp_end = response.get("timestamp_end")
        self.timestamp_start = response.get("timestamp_start")


class ProxyHttpScan(object):
    def __init__(self):
        pass

    @staticmethod
    def list():
        result_list = []
        proxy_http_scan_dict = Xcache.get_proxy_http_scan_dict()
        for module_uuid in proxy_http_scan_dict:
            one_result = proxy_http_scan_dict.get(module_uuid)
            module_intent = one_result.pop("module")
            loadpath = one_result.get("loadpath")

            one_result["_module_uuid"] = module_uuid
            one_result["moduleinfo"] = Xcache.get_moduleconfig(loadpath)
            try:
                one_result["opts"] = module_intent.get_readable_opts()
            except Exception as E:
                logger.warning(E)
                Xcache.delete_proxy_http_scan_dict(module_uuid)
                continue

            result_list.append(one_result)
        context = data_return(200, result_list, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        return context

    @staticmethod
    def create(loadpath, custom_param):
        module_uuid = str(uuid.uuid1())

        try:
            class_intent = importlib.import_module(loadpath)
            module_intent = class_intent.PostModule(custom_param=json.loads(custom_param))
        except Exception as E:
            context = data_return(306, {}, ProxyHttpScan_MSG_ZH.get(306), ProxyHttpScan_MSG_EN.get(306))
            return context

        if Xcache.add_proxy_http_scan_dict(module_uuid, loadpath, custom_param, module_intent):
            context = data_return(201, {}, ProxyHttpScan_MSG_ZH.get(201), ProxyHttpScan_MSG_EN.get(201))
            return context
        else:
            context = data_return(306, {}, ProxyHttpScan_MSG_ZH.get(306), ProxyHttpScan_MSG_EN.get(306))
            return context

    @staticmethod
    def destory(module_uuid):
        if Xcache.delete_proxy_http_scan_dict(module_uuid):
            context = data_return(204, {"_module_uuid": module_uuid}, ProxyHttpScan_MSG_ZH.get(204),
                                  ProxyHttpScan_MSG_EN.get(204))
            return context
        else:
            context = data_return(304, {}, ProxyHttpScan_MSG_ZH.get(304), ProxyHttpScan_MSG_EN.get(304))
            return context

    @staticmethod
    def store_request_response_from_sub(message=None):
        """处理msf发送的notice信息print_XXX_redis"""
        body = message.get('data')
        try:
            data_dict = json.loads(body)
            request_data = data_dict.get("request")
            response_data = data_dict.get("response")
            data = data_dict.get("data")
        except Exception as E:
            logger.exception(E)
            return False

        conf = Xcache.get_proxy_http_scan_conf()
        if conf.get("flag") is not True:
            return

        proxy_http_scan_dict = Xcache.get_proxy_http_scan_dict()
        for module_uuid in proxy_http_scan_dict:
            one_result = proxy_http_scan_dict.get(module_uuid)
            module_intent = one_result.get("module")
            try:
                module_intent.callback(request=ProxyRequest(request_data), response=ProxyResponse(response_data),
                                       data=data)
            except Exception as E:
                logger.exception(E)
                continue
