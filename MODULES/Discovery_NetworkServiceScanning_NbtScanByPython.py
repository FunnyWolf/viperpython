# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :


import base64
import json

from Lib.ModuleAPI import *


class PostModule(PostMSFPythonWithParamsModule):
    NAME_ZH = "内网Netbios&SMB扫描"
    DESC_ZH = "通过 NBNS 协议获取 NetBIOS Name.\n" \
              "通过 139（默认）或者 445 探测系统相关信息.\n"

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows", "Linux"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", "Root"]  # 所需权限
    ATTCK = ["T1046"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/wgghxf"]
    REFERENCES = ["https://github.com/iiilin/inbtscan"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionStr(name='ipstr', name_tag="IP地址", required=True, desc="扫描IP地址列表(10.10.10.10,10.10.11-13,10.10.11.1/24)"),
        OptionEnum(name='port',
                   name_tag="端口",
                   desc="139端口支持netbios+smb扫描,445端口支持smb扫描",
                   required=True,
                   default=139,
                   enum_list=[
                       {'name': "139", 'value': 139},
                       {'name': "445", 'value': 445},
                   ]),
        OptionInt(name='connect_time_out', name_tag="连接超时时间(毫秒)", desc="网络扫描过程中每个网络连接的超时时间,请依据主机内网网络环境进行调整(通常小于500ms)",
                  default=100),
        OptionInt(name='timeout', name_tag="模块执行超时时间(秒)", desc="模块执行的超时时间", required=True, default=600),

        # OptionInt(name='max_threads', name_tag="扫描线程数", desc="扫描线程数(最大值20)", default=10),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("inbt.py")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        # session 检查

        self.session = Session(self._sessionid)
        if self.session.is_alive is not True:
            return False, "当前session不可用"

        # 参数检查
        ipstr = self.param('ipstr')
        timeout = self.param('timeout')
        connect_time_out = self.param('connect_time_out')
        # max_threads = self.param('max_threads')

        try:

            iplist = self.str_to_ips(ipstr)

            if len(iplist) > 510:
                return False, "扫描IP范围过大(超过510),请缩小范围"
            elif len(iplist) < 0:
                return False, "输入的IP地址格式有误,未识别到有效IP地址,请重新输入"
            self.set_script_param('ipstr', ipstr)
        except Exception as E:
            return False, "输入的IP格式有误,请重新输入"
        if self.param('port') not in [139, 445]:
            self.set_script_param('port', 139)
        else:
            self.set_script_param('port', self.param("port"))

        if timeout <= 0 or timeout > 3600:
            return False, "输入的模块超时时间有误(最大值3600),请重新输入"
        if connect_time_out <= 0 or connect_time_out > 3000:
            return False, "输入的连接超时时间有误(最大值3000),请重新输入"
        # if max_threads <= 0 or max_threads > 20:
        #     return False, "输入的扫描线程数有误(最大值20),请重新输入"

        self.set_script_param('time_out', connect_time_out / 1000)
        # self.set_script_param('max_threads', max_threads)
        self.set_script_timeout(timeout)

        # return False, None
        return True, None

    def callback(self, status, message, data):
        if status:
            try:
                result = base64.b64decode(bytes(data, encoding="utf8")).decode('ascii')
                portservice_list = json.loads(result)
            except Exception as E:
                self.log_error("脚本输出解析失败")
                self.log_error(E)
                self.log_error(data)
                return
            if len(portservice_list) == 0:
                self.log_info("脚本执行完成,但是未扫描到有效数据,可能是由于对方网络关闭,请检查主机netstat信息后重试")
                self.log_info("如果确认网络连接正常但扫描无结果,请使用Meterpreter命令行中的'重置python插件功能'重置后重新扫描")
                return

            self.log_info("扫描结果")
            for portservice in portservice_list:
                # 输出部分
                ipaddress = portservice.get("ipaddress")

                # 新增主机
                result = self.add_host(ipaddress, source=self.host_ipaddress, linktype="scan",
                                       data={"method": "netbios"})

                portservice.pop("ipaddress")  # 弹出ipaddress数据
                HostInfo.update_info(ipaddress, portservice)

                group = portservice.get("group")
                unique = portservice.get("unique")
                self.log_raw(f"{ipaddress}    {group}/{unique}")

                os_version = portservice.get("os_version")
                major_version = portservice.get("major_version")
                minor_version = portservice.get("minor_version")
                build_number = portservice.get("bulid_number")
                self.log_raw(os_version)
                self.log_raw(f"Build Number: {build_number}")
                self.log_raw(f"Major Version: {major_version}")
                self.log_raw(f"Minor Version: {minor_version}")

                ntlm_current_revision = portservice.get("ntlm_current_revision")
                self.log_raw(f"Ntlm Current Revision: {ntlm_current_revision}")

                name_list = portservice.get("name_list")

                self.log_raw("\nNames:")
                if isinstance(name_list, list):
                    for name in name_list:
                        self.log_raw("  ".join(name))

                netbios_item = portservice.get("netbios_item")

                self.log_raw("\nNetbios Item:")
                if isinstance(netbios_item, list):
                    for netbios in netbios_item:
                        for key in netbios:
                            self.log_raw(f"{key}: {netbios[key]}")
                self.log_raw("-----------------------------------------------\n\n")

        else:
            self.log_error("模块执行失败")
            self.log_error(message)
