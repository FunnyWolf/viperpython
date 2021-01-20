# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

#
#

from PostModule.lib.ModuleTemplate import TAG2CH, PostMSFRawModule
from PostModule.lib.OptionAndResult import Option, register_options
from PostModule.lib.Vulnerability import Vulnerability


class PostModule(PostMSFRawModule):
    NAME = "CVE-2019-0708 扫描"
    DESC = "模块使用验证代码扫描目标主机的3389端口,根据目标回复包判断对方是否修复了CVE-2019-0708漏洞.\n" \
           "验证模块可以用于内网扫描及外网扫描,验证代码不会导致目标蓝屏."

    REQUIRE_SESSION = False
    MODULETYPE = TAG2CH.Lateral_Movement
    OPTIONS = register_options([
        Option(name='startip', name_tag="起始IP", type='str', required=False, desc="扫描的起始IP", ),
        Option(name='stopip', name_tag="结束IP", type='str', required=False, desc="扫描的结束IP", ),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "auxiliary"
        self.mname = "scanner/rdp/cve_2019_0708_bluekeep_api"

    def check(self):
        """执行前的检查函数"""
        self.set_option(key='ShowProgress', value=False)

        # 设置RHOSTS参数
        startip = self.param('startip')
        stopip = self.param('stopip')
        if startip is None and stopip is None:
            self.set_option(key='RHOSTS', value=self.host_ipaddress)
        else:
            try:
                ipnum = self.dqtoi(stopip) - self.dqtoi(startip)
                if ipnum > 25 + 6:
                    return False, "扫描IP范围过大(超过256),请缩小范围"
                elif ipnum < 0:
                    return False, "输入的起始IP与结束IP有误,请重新输入"
                self.set_option('RHOSTS', "{}-{}".format(startip, stopip))
            except Exception as E:
                return False, "输入的IP格式有误,请重新输入"

        return True, None

    def callback(self, status, message, data):

        if status:
            for human_result in data:
                ipaddress = human_result.get('host')
                if human_result.get("result") == "VULNERABLE":
                    self.log_good("{} 存在CVE-2019-0708漏洞".format(ipaddress))
                    Vulnerability.add_vulnerability(hid_or_ipaddress=ipaddress,
                                                    source_module_loadpath=self.loadpath,
                                                    extra_data={},
                                                    desc=None)
                elif human_result.get("result") == "UNVULNERABLE":
                    self.log_error("{} 不存在漏洞".format(ipaddress))
                elif human_result.get("result") == "UNREACHABLE":
                    self.log_error("{} 无法访问".format(ipaddress))
                elif human_result.get("result") == "UNDETECT":
                    self.log_error("{} 检测失败".format(ipaddress))
                else:
                    pass
        else:
            self.log_error("模块执行失败")
            self.log_error(message)

    # @staticmethod
    # def format_result(result):
    #     lines = result.split('\n')
    #     human_results = []
    #     for line in lines:
    #         import re
    #         vuln_re_search = re.search('^\[\+\] (.+)\s+- The target is vulnerable\.', line)
    #         novuln_re_search = re.search('^\[\*\] (.+)\s+- The target is not exploitable\.', line)
    #         noconnect_re_search = re.search(
    #             '^\[\*\] (.+)\s+- The target service is not running, or refused our connection\.', line)
    #         if vuln_re_search is not None:
    #             host_os_tuple = vuln_re_search.groups()
    #             try:
    #                 ipaddress = host_os_tuple[0].split(':')[0]
    #                 # os = host_os_tuple[1]
    #                 human_results.append({'ipaddress': ipaddress, 'vulnerable': "vuln"})
    #                 continue
    #             except Exception as E:
    #                 pass
    #         if novuln_re_search is not None:
    #             host_os_tuple = novuln_re_search.groups()
    #             try:
    #                 ipaddress = host_os_tuple[0].split(':')[0]
    #                 # os = host_os_tuple[1]
    #                 human_results.append({'ipaddress': ipaddress, 'vulnerable': "novuln"})
    #                 continue
    #             except Exception as E:
    #                 pass
    #         if noconnect_re_search is not None:
    #             host_os_tuple = noconnect_re_search.groups()
    #             try:
    #                 ipaddress = host_os_tuple[0].split(':')[0]
    #                 # os = host_os_tuple[1]
    #                 human_results.append({'ipaddress': ipaddress, 'vulnerable': "noconnect"})
    #                 continue
    #             except Exception as E:
    #                 pass
    #     return human_results
