# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *
from WebDatabase.documents import CompanyICPDocument


class PostModule(WebPythonModule):
    NAME_ZH = "自动化信息收集(通过公司名称)"
    DESC_ZH = "自动化信息收集(通过公司名称)"

    NAME_EN = "Automatic information collection (by company name)"
    DESC_EN = "Automatic information collection (by company name)"
    MODULETYPE = TAG2TYPE.Web_Auto_Module
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='company_name',
                  tag_zh="公司名称",
                  desc_zh="公司名称",
                  tag_en="Company Name",
                  desc_en="Company Name",
                  required=True,
                  ),

        OptionSelectMulti(name='company_scan',
                          tag_zh="公司信息收集插件", desc_zh="公司信息收集插件",
                          tag_en="Company Info plugin", desc_en="Company Info plugin",
                          required=True,
                          default=['aiqicha'],
                          options=[
                              {'tag_zh': '爱企查', 'tag_en': 'Aiqicha', 'value': 'aiqicha'},
                          ]),

        OptionSelectMulti(name='subdomain_scan',
                          tag_zh="子域名扫描插件", desc_zh="子域名扫描插件",
                          tag_en="Subdomain Scan Plugin", desc_en="Subdomain Scan Plugin",
                          required=True,
                          default=['quake'],
                          options=[
                              {'tag_zh': '360 Quake', 'tag_en': '360 Quake', 'value': 'quake'},
                          ]),

        OptionSelectMulti(name='port_scan',
                          tag_zh="端口扫描插件", desc_zh="端口扫描插件",
                          tag_en="Port Scan Plugin", desc_en="Port Scan Plugin",
                          required=True,
                          default=['quake'],
                          options=[
                              {'tag_zh': '360 Quake', 'tag_en': '360 Quake', 'value': 'quake'},
                          ]),

        OptionSelectMulti(name='fingerprint_scan',
                          tag_zh="指纹识别插件", desc_zh="指纹识别插件",
                          tag_en="Fingerprint Scan Plugin", desc_en="Fingerprint Scan Plugin",
                          required=True,
                          default=['quake'],
                          options=[
                              {'tag_zh': '360 Quake', 'tag_en': '360 Quake', 'value': 'quake'},
                          ]),

        OptionSelectMulti(name='screenshot_scan',
                          tag_zh="网站截图插件", desc_zh="网站截图插件",
                          tag_en="Screenshot Plugin", desc_en="Screenshot Plugin",
                          # required=True,
                          default=['quake'],
                          options=[
                              {'tag_zh': '360 Quake', 'tag_en': '360 Quake', 'value': 'quake'},
                          ]),

        OptionSelectMulti(name='cdn_scan',
                          tag_zh="CDN检测插件", desc_zh="CDN检测插件",
                          tag_en="CDN Detect Plugin", desc_en="CDN Detect Plugin",
                          # required=True,
                          default=['cdncheck'],
                          options=[
                              {'tag_zh': 'CDNCheck', 'tag_en': 'CDNCheck', 'value': 'cdncheck'},
                          ]),

        OptionSelectMulti(name='waf_scan',
                          tag_zh="WAF检测插件", desc_zh="WAF检测插件",
                          tag_en="WAF Detect Plugin", desc_en="WAF Detect Plugin",
                          # required=True,
                          default=['wafw00f'],
                          options=[
                              {'tag_zh': 'Wafw00f', 'tag_en': 'Wafw00f', 'value': 'wafw00f'},
                          ]),

        OptionSelectMulti(name='vulnerability_scan',
                          tag_zh="漏洞检测插件", desc_zh="漏洞检测插件",
                          tag_en="Vulnerability Scan Plugin", desc_en="Vulnerability Scan Plugin",
                          # required=True,
                          default=[],
                          options=[
                              {'tag_zh': 'Nuclei', 'tag_en': 'Nuclei', 'value': 'nuclei'},
                          ]),
    ])

    def __init__(self, project_id, input_list: list, custom_param):
        super().__init__(project_id, input_list, custom_param)

    def check(self):
        """执行前的检查函数"""
        ## TODO 检查使用的工具是否可用
        return True, ""

    def run(self):
        company_name = self.param('company_name')
        company_scan: list = self.param('company_scan')
        subdomain_scan: list = self.param('subdomain_scan')
        port_scan: list = self.param('port_scan')
        fingerprint_scan: list = self.param('fingerprint_scan')
        screenshot_scan: list = self.param('screenshot_scan')
        cdn_scan: list = self.param('cdn_scan')
        waf_scan: list = self.param('waf_scan')
        vulnerability_scan: list = self.param('vulnerability_scan')

        dataset = DataSet()
        dataset.set_project_id(self.project_id)

        # 通过公司名称获取公司基本信息
        self.log_info("开始获取公司基本信息", "Start getting basic company information")
        for company_scan_tool in company_scan:
            if company_scan_tool == "aiqicha":
                self.log_info(f"运行 {company_scan_tool}", f"Run {company_scan_tool}")

                aiqicha = Aiqicha()
                if aiqicha.init_conf_from_cache() is not True:
                    self.log_error("Aiqicha 配置无效", "Aiqicha configuration invalid")
                    continue
                aiqicha.search_by_name(company_name, dataset)

                self.log_info(f"完成 {company_scan_tool}", f"Finish {company_scan_tool}")
            else:
                self.log_error(f"未知的公司信息收集插件: {company_scan_tool}",
                               f"Unknown company information collection plugin: {company_scan_tool}")

        # 整理后续需要的icp信息
        root_domain_list = []
        ipdomain_list = []
        for company_icp in dataset.companyICPList:
            company_icp: CompanyICPDocument
            if api.is_ipaddress(company_icp.domain):
                ipdomain_list.append({"domain": company_icp.domain, "company_name": company_icp.company_name})
            elif api.is_root_domain(domain=company_icp.domain):
                root_domain_list.append({"domain": company_icp.domain, "company_name": company_icp.company_name})
            else:
                self.log_warn(f"无法识别的域名/IP: {company_icp.domain} {company_icp.company_name}",
                              f"Unrecognized domain/IP: {company_icp.domain} {company_icp.company_name}")

        # 子域名扫描
        self.log_info("开始子域名扫描", "Start subdomain scan")
        for subdomain_scan_tool in subdomain_scan:
            if subdomain_scan_tool == "quake":
                self.log_info(f"运行 {subdomain_scan_tool}", f"Run {subdomain_scan_tool}")

                quake = Quake()
                try:
                    quake.init_conf_from_cache()
                except CustomException as e:
                    self.log_except(e.msg_zh, e.msg_en)
                    continue
                except Exception as E:
                    self.log_except(E)
                    continue

                for one in root_domain_list[0:5]:
                    source_key = f"domain:\"{one.get('domain')}\""
                    flag = quake.search_by_query_str(source_key, dataset, company_name=one.get('company_name'))
                    self.log_info(f"Quake Search : {source_key} Count: {flag}")

                self.log_info(f"完成 {subdomain_scan_tool}", f"Finish {subdomain_scan_tool}")
            else:
                self.log_error(f"未知的子域名扫描插件: {subdomain_scan_tool}",
                               f"Unknown subdomain scan plugin: {subdomain_scan_tool}")

        # 端口扫描
        self.log_info("开始端口扫描", "Start port scan")
        for port_scan_tool in port_scan:
            if port_scan_tool == "quake":
                self.log_info(f"运行 {port_scan_tool}", f"Run {port_scan_tool}")
                quake = Quake()
                try:
                    quake.init_conf_from_cache()
                except CustomException as e:
                    self.log_except(e.msg_zh, e.msg_en)
                    continue
                except Exception as E:
                    self.log_except(E)
                    continue

                for one in ipdomain_list:
                    source_key = f"ip:\"{one.get('domain')}\""
                    flag = quake.search_by_query_str(source_key, dataset, company_name=one.get('company_name'))
                    self.log_info(f"Quake Search : {source_key} Count: {flag}")

                self.log_info(f"完成 {port_scan_tool}", f"Finish {port_scan_tool}")
            else:
                self.log_error(f"未知的端口扫描插件: {port_scan_tool}",
                               f"Unknown port scan plugin: {port_scan_tool}")

        # cdn 检测
        self.log_info("开始CDN检测", "Start CDN detection")
        for cdn_scan_tool in cdn_scan:
            if cdn_scan_tool == "cdncheck":
                self.log_info(f"运行 {cdn_scan_tool}", f"Run {cdn_scan_tool}")
                cdncheck = CDNCheck()
                cdncheck.check_by_dataset(dataset)
                self.log_info(f"完成 {cdn_scan_tool}", f"Finish {cdn_scan_tool}")
            else:
                self.log_error(f"未知的CDN检测插件: {cdn_scan_tool}",
                               f"Unknown CDN detection plugin: {cdn_scan_tool}")

        urls = dataset.get_urls()

        # 存储信息到数据库
        self.log_info("存储数据到数据库", "Save data to database")

        dataset.save_to_db()

        # waf 检测
        self.log_info("开始WAF检测", "Start WAF detection")
        for waf_scan_tool in waf_scan:
            if waf_scan_tool == "wafw00f":
                self.log_info(f"运行 {waf_scan_tool}", f"Run {waf_scan_tool}")
                wafw00f = WafCheck()
                wafw00f.scan(urls=urls, dataset=dataset)
                self.log_info(f"完成 {waf_scan_tool}", f"Finish {waf_scan_tool}")
            else:
                self.log_error(f"未知的WAF检测插件: {waf_scan_tool}",
                               f"Unknown WAF detection plugin: {waf_scan_tool}")

        # vulnerability 检测
        self.log_info("开始漏洞检测", "Start vulnerability detection")
        for vulnerability_scan_tool in vulnerability_scan:
            if vulnerability_scan_tool == "nuclei":
                self.log_info(f"运行 {vulnerability_scan_tool}", f"Run {vulnerability_scan_tool}")
                nuclei = NucleiAPI()
                nuclei.scan(urls=urls, dataset=dataset)
                self.log_info(f"完成 {vulnerability_scan_tool}", f"Finish {vulnerability_scan_tool}")
            else:
                self.log_error(f"未知的漏洞检测插件: {vulnerability_scan_tool}",
                               f"Unknown vulnerability detection plugin: {vulnerability_scan_tool}")
        # 存储信息到数据库
        self.log_info("存储数据到数据库", "Save data to database")

        dataset.save_to_db()

        self.log_info("模块运行完成", "Module operation completed")
