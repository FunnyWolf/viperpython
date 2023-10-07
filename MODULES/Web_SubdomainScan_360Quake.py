# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "360 Quake子域名收集"
    DESC_ZH = "调用360 Quake进行子域名"

    NAME_EN = "360 Quake subdomain collection"
    DESC_EN = "Call 360 Quake to perform subdomain"
    MODULETYPE = TAG2TYPE.Web_Subdomain_Scan
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='Domain',
                  tag_zh="主域名",
                  desc_zh="主域名",
                  tag_en="Domain",
                  desc_en="Domain"),
        OptionInt(name='MaxSize',
                  tag_zh="最大数量",
                  desc_zh="最大数量",
                  tag_en="MaxSize",
                  desc_en="MaxSize",
                  default=1000),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.quake_client = Quake()

    def check(self):
        """执行前的检查函数"""
        if self.param("MaxSize") > 1000:
            return False, "MaxSize不能大于1000", "MaxSize cannot be greater than 1000"
        elif self.param("MaxSize") < 0:
            return False, "MaxSize不能小于0", "MaxSize cannot be less than 0"
        if self.quake_client.init_conf_from_cache() is not True:
            return False, "Quake 配置无效", "Quake configuration invalid"
        return True, ""

    def run(self):
        self.log_info(f"主域名: {self.param('Domain')}", f"Domain: {self.param('Domain')}")
        msg, items = self.quake_client.query_by_domain(domain=self.param('Domain'), size=self.param('MaxSize'))
        if items is None:
            self.log_error(f"调用Quake失败: {msg}", f"Call Quake failed : {msg}")
            return False

        for item in items:
            update_time = self.str_to_timestamp(item.get("time"))
            source_key = f"Domain:{self.param('Domain')}"
            ip = item.get("ip")
            port = item.get("port")
            source = "Quake"

            service_config = item.get("service")
            service_name = service_config.get("name")

            # IPDomainModel
            IPDomain.add_or_update(ipdomain=ip, type="ip", source=source,
                                   source_key=source_key, data=item,
                                   update_time=update_time)

            # PortServiceModel
            WebPortService.add_or_update(ipdomain=ip, port=port, source=source,
                                         source_key=source_key, data=service_config,
                                         update_time=update_time,
                                         transport=item.get("transport"), service=service_config.get("name"),
                                         version=service_config.get("version"))

            if service_name in ["http/ssl", "http"]:
                http_config = service_config.get("http")
                # HttpBaseModel
                HttpBase.add_or_update(ipdomain=ip, port=port, source=source,
                                       source_key=source_key, data=http_config,
                                       update_time=update_time,
                                       title=http_config.get("title"), status_code=http_config.get("status_code"),
                                       header=http_config.get("response_headers"),
                                       response=service_config.get("response"),
                                       body=http_config.get("body"))

                # HttpFavicon
                if http_config.get("favicon"):
                    favicon_config = http_config.get("favicon")
                    favicon_base64 = Quake.get_images_base64(favicon_config.get("s3_url"))
                    HttpFavicon.add_or_update(ipdomain=ip, port=port,
                                              source=source, source_key=source_key, data=http_config,
                                              update_time=update_time,
                                              content=favicon_base64)
                # HttpComponentModel
                if item.get("components"):
                    components = item.get("components")
                    for component in components:
                        product_type = component.pop("product_type")
                        product_catalog = component.pop("product_catalog")
                        product_dict_values = component
                        HttpComponent.add_or_update(ipdomain=ip, port=port,
                                                    source=source, source_key=source_key, data=http_config,
                                                    update_time=update_time,
                                                    product_dict_values=product_dict_values,
                                                    product_type=product_type,
                                                    product_catalog=product_catalog)
                # DomainICPModel
                if http_config.get("icp"):

                # HttpScreenshot
                if item.get("images"):
                    for image in item.get("images"):
                        image_base64 = Quake.get_images_base64(image.get("s3_url"))
                        HttpScreenshot.add_or_update(ipdomain=ip, port=port,
                                                     source=source, source_key=source_key, data=http_config,
                                                     update_time=update_time,
                                                     content=image_base64)
                if service_name in ["http/ssl"]:
                    http_config = service_config.get("http")

                    # HttpCert
                    tls_jarm = service_config.get("tls-jarm")
                    if tls_jarm:
                        jarm_hash = tls_jarm.get("jarm_hash")
                    else:
                        jarm_hash = None
                    HttpCert.add_or_update(ipdomain=ip, port=port,
                                           source=source, source_key=source_key, data=http_config,
                                           update_time=update_time,
                                           cert=service_config.get("cert"),
                                           jarm=jarm_hash)

                # LocationModel

        return True
