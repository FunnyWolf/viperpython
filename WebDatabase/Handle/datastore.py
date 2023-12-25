import time
from urllib.parse import urlparse

import urllib3

from Lib.External.cdncheck import CDNCheck
from Lib.api import urlParser
from Lib.configs import DEFAULT_PROJECT_ID
from Lib.file import File
from Lib.timeapi import TimeAPI
from WebDatabase.Handle.cdn import CDN
from WebDatabase.Handle.cert import Cert
from WebDatabase.Handle.component import Component
from WebDatabase.Handle.dnsrecord import DNSRecord
from WebDatabase.Handle.domainicp import DomainICP
from WebDatabase.Handle.httpbase import HttpBase
from WebDatabase.Handle.httpfavicon import HttpFavicon
from WebDatabase.Handle.ipdomain import IPDomain
from WebDatabase.Handle.location import Location
from WebDatabase.Handle.port import Port
from WebDatabase.Handle.screenshot import Screenshot
from WebDatabase.Handle.service import Service
from WebDatabase.Handle.vulnerability import Vulnerability
from WebDatabase.Handle.waf import WAF

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DataStore(object):
    @staticmethod
    def quake_result(items, project_id=DEFAULT_PROJECT_ID, source={}):
        for item in items:
            if "." in item.get("time"):
                format = '%Y-%m-%dT%H:%M:%S.%fZ'
            else:
                format = '%Y-%m-%dT%H:%M:%SZ'
            update_time = TimeAPI.str_to_timestamp(item.get("time"), format)

            ip = item.get("ip")
            domain = item.get("domain")

            port = item.get("port")

            service_config = item.get("service")
            response = service_config.get("response")
            response_hash = service_config.get("response_hash")
            dns_reocord = service_config.get("dns")

            service_name = service_config.get("name")

            location_config = item.get("location")
            isp = location_config.get("isp")
            asname = location_config.get("asname")

            components = item.get("components")
            images = item.get("images")

            webbase_dict = {
                'source': source,
                'update_time': update_time,
                # 'data': item,
            }

            # DNS 信息
            if dns_reocord:
                a = dns_reocord.get("a")
                cname = dns_reocord.get("cname")

                if a:
                    DNSRecord.update_or_create(domain=domain, type="A", value=a, webbase_dict=webbase_dict)
                if cname:
                    DNSRecord.update_or_create(domain=domain, type="CNAME", value=cname, webbase_dict=webbase_dict)

                # CDN
                if cname:
                    for one_cname in cname:
                        cdn_record = CDNCheck.check(one_cname)
                        if cdn_record:
                            CDN.update_or_create(ipdomain=domain, flag=True, domain=cdn_record.get("domain"),
                                                 name=cdn_record.get("name"), link=cdn_record.get("link"),
                                                 webbase_dict=webbase_dict)
                    else:
                        CDN.update_or_create(ipdomain=domain, flag=False, domain=None, name=None, link=None,
                                             webbase_dict=webbase_dict)
                else:
                    CDN.update_or_create(ipdomain=domain, flag=False, domain=None, name=None, link=None,
                                         webbase_dict=webbase_dict)

            if domain is None:
                ipdomain = ip
            else:
                ipdomain = domain

            IPDomain.update_or_create(project_id=project_id,
                                      ipdomain=ipdomain,
                                      webbase_dict=webbase_dict)

            Location.update_or_create(ipdomain=ipdomain,
                                      isp=isp,
                                      asname=asname,
                                      geo_info=location_config,
                                      webbase_dict=webbase_dict)

            Port.update_or_create(ipdomain=ipdomain, port=port, webbase_dict=webbase_dict)
            Service.update_or_create(ipdomain=ipdomain, port=port,
                                     response=response,
                                     response_hash=response_hash,
                                     transport=item.get("transport"),
                                     service=service_name,
                                     version=service_config.get("version"),
                                     webbase_dict=webbase_dict)

            # ComponentModel
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

            # Screenshot
            if images:
                for image in images:
                    image_base64 = File.get_images_base64(image.get("s3_url"))
                    Screenshot.update_or_create(ipdomain=ipdomain, port=port, content=image_base64,
                                                webbase_dict=webbase_dict)
            # Cert
            if service_name.endswith("/ssl"):
                tls_jarm = service_config.get("tls-jarm")
                if tls_jarm:
                    jarm_hash = tls_jarm.get("jarm_hash")
                else:
                    jarm_hash = None

                try:
                    subject = service_config["tls"]["handshake_log"]["server_certificates"]["certificate"]["parsed"][
                        "subject"]
                    subject["country"] = subject["country"][0]
                    subject["organization"] = subject["organization"][0]
                    subject["province"] = subject["province"][0]
                    subject["common_name"] = subject["common_name"][0]
                    subject["locality"] = subject["locality"][0]
                except Exception as _:
                    subject = {}

                Cert.update_or_create(ipdomain=ipdomain, port=port,
                                      cert=service_config.get("cert"),
                                      jarm=jarm_hash,
                                      subject=subject,
                                      webbase_dict=webbase_dict
                                      )

            # http
            if service_name.startswith("http"):
                http_config = service_config.get("http")
                # HttpBaseModel
                HttpBase.update_or_create(ipdomain=ipdomain, port=port,
                                          title=http_config.get("title"),
                                          status_code=http_config.get("status_code"),
                                          header=http_config.get("response_headers"),
                                          body=http_config.get("body"),
                                          webbase_dict=webbase_dict
                                          )

                # HttpFavicon
                if http_config.get("favicon"):
                    favicon_config = http_config.get("favicon")
                    favicon_base64 = File.get_images_base64(favicon_config.get("s3_url"))
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

    @staticmethod
    def hunter_result(items, project_id=DEFAULT_PROJECT_ID, source={}):
        for item in items:
            update_time = TimeAPI.str_to_timestamp(item.get("updated_at"), "%Y-%m-%d")

            ip = item.get("ip")
            domain = item.get("domain")

            port = item.get("port")

            response = item.get("banner")

            service_name = item.get("protocol")
            if service_name == "https":
                service_name = "http/ssl"

            isp = item.get("isp")
            asname = item.get("as_org")

            location_config = {"conuntry_cn": item.get("conuntry"), "province_cn": item.get("province"),
                               "city_cn": item.get("city"), }

            components = item.get("component")

            webbase_dict = {
                'source': source,
                'update_time': update_time,
            }

            if domain is None:
                ipdomain = ip
            else:
                ipdomain = domain

            IPDomain.update_or_create(project_id=project_id,
                                      ipdomain=ipdomain,
                                      webbase_dict=webbase_dict)

            Location.update_or_create(ipdomain=ipdomain,
                                      isp=isp,
                                      asname=asname,
                                      geo_info=location_config,
                                      webbase_dict=webbase_dict)

            Port.update_or_create(ipdomain=ipdomain, port=port, webbase_dict=webbase_dict)
            Service.update_or_create(ipdomain=ipdomain, port=port,
                                     response=response,
                                     transport=item.get("base_protocol"),
                                     service=service_name,
                                     webbase_dict=webbase_dict)

            # ComponentModel
            if components:
                components = item.get("component")
                for component in components:
                    product_name = component.get("name")
                    product_version = component.get("version")
                    product_dict_values = component

                    Component.update_or_create(ipdomain=ipdomain,
                                               port=port,
                                               product_name=product_name,
                                               product_version=product_version,
                                               product_dict_values=product_dict_values,
                                               webbase_dict=webbase_dict
                                               )
            # http
            if service_name.startswith("http"):
                # HttpBaseModel
                HttpBase.update_or_create(ipdomain=ipdomain, port=port,
                                          title=item.get("web_title"),
                                          status_code=item.get("status_code"),
                                          webbase_dict=webbase_dict
                                          )

                # DomainICPModel
                if item.get("company"):
                    domain_icp = item.get("domain")
                    unit = item.get("company")
                    DomainICP.update_or_create(ipdomain=domain_icp,
                                               license=item.get("number"),
                                               unit=unit, webbase_dict=webbase_dict)

    @staticmethod
    def fofa_result(items, project_id=DEFAULT_PROJECT_ID, source={}):
        for item in items:
            format = '%Y-%m-%d %H:%M:%S'
            update_time = TimeAPI.str_to_timestamp(item.get("lastupdatetime"), format)

            ip = item.get("ip")
            url = item.get("host")
            urlparse_result = urlparse(url)
            domain = urlparse_result.hostname

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

            cdn_record = CDNCheck.check(cname)
            if cdn_record:
                CDN.update_or_create(ipdomain=domain, flag=True, domain=cdn_record.get("domain"),
                                     name=cdn_record.get("name"), link=cdn_record.get("link"),
                                     webbase_dict=webbase_dict)
            else:
                CDN.update_or_create(ipdomain=domain, flag=False, domain=None, name=None, link=None,
                                     webbase_dict=webbase_dict)

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
            Port.update_or_create(ipdomain=ipdomain, port=port, webbase_dict=webbase_dict)
            Service.update_or_create(ipdomain=ipdomain, port=port,
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

    @staticmethod
    def zoomeye_result(items, project_id=DEFAULT_PROJECT_ID, source={}):
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

            Port.update_or_create(ipdomain=ipdomain, port=port, webbase_dict=webbase_dict)
            Service.update_or_create(ipdomain=ipdomain, port=port,
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

    @staticmethod
    def wafcheck_result(items, project_id=DEFAULT_PROJECT_ID, source={}):
        for item in items:
            update_time = int(time.time())
            url = item.get("url")
            trigger_url = item.get("trigger_url")
            detected = item.get("detected")
            firewall = item.get("firewall")
            manufacturer = item.get("manufacturer")
            hostname, port, path, query, ssl = urlParser(url)
            if port is None:
                if ssl:
                    port = 443
                else:
                    port = 80
            webbase_dict = {
                'source': source,
                'update_time': update_time,
            }

            IPDomain.update_or_create(project_id=project_id,
                                      ipdomain=hostname,
                                      webbase_dict=webbase_dict)
            if detected is None:
                webbase_dict = {
                    'alive': False,
                    'source': source,
                    'update_time': update_time,
                }
                Port.update_or_create(ipdomain=hostname, port=port, webbase_dict=webbase_dict)
            else:
                webbase_dict_port = {
                    'alive': True,
                    'source': source,
                    'update_time': update_time,
                }
                Port.update_or_create(ipdomain=hostname, port=port, webbase_dict=webbase_dict_port)

                webbase_dict = {
                    'source': source,
                    'update_time': update_time,
                }
                WAF.update_or_create(ipdomain=hostname, port=port, flag=detected, trigger_url=trigger_url,
                                     name=firewall,
                                     manufacturer=manufacturer,
                                     webbase_dict=webbase_dict)

    @staticmethod
    def cdncheck_result(item, project_id=DEFAULT_PROJECT_ID, source={}):
        update_time = int(time.time())
        webbase_dict = {
            'source': source,
            'update_time': update_time,
            # 'data': item,
        }
        CDN.update_or_create(ipdomain=item.get('ipdomain'), flag=item.get('flag'), domain=item.get("domain"),
                             name=item.get("name"), link=item.get("link"),
                             webbase_dict=webbase_dict)

    @staticmethod
    def subdomain_result(items, project_id=DEFAULT_PROJECT_ID, source={}):
        for item in items:
            update_time = int(time.time())
            ipdomain = item.get("ipdomain")
            webbase_dict = {
                'source': source,
                'update_time': update_time,
            }
            IPDomain.update_or_create(project_id=project_id,
                                      ipdomain=ipdomain,
                                      webbase_dict=webbase_dict)

    @staticmethod
    def nuclei_result(items, project_id=DEFAULT_PROJECT_ID, source={}):
        for item in items:
            update_time = int(time.time())
            url = item.get("url")
            hostname, port, path, query, ssl = urlParser(url)
            if port is None:
                if ssl:
                    port = 443
                else:
                    port = 80

            webbase_dict = {
                'source': source,
                'update_time': update_time,
            }

            IPDomain.update_or_create(project_id=project_id,
                                      ipdomain=hostname,
                                      webbase_dict=webbase_dict)

            webbase_dict_port = {
                'alive': True,
                'source': source,
                'update_time': update_time,
            }
            Port.update_or_create(ipdomain=hostname, port=port, webbase_dict=webbase_dict_port)

            webbase_dict = {
                'data': item,
                'source': source,
                'update_time': update_time,
            }
            info = item.get("info")
            name = info.get("name")
            description = info.get("description")
            severity = info.get("severity")
            key = item.get("template-id")
            tool = "nuclei"
            Vulnerability.update_or_create(ipdomain=hostname, port=port, name=name, description=description,
                                           severity=severity,
                                           key=key, tool=tool,
                                           webbase_dict=webbase_dict)
