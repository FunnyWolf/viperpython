# -*- coding: utf-8 -*-
# @File  : configs.py
# @Date  : 2019/3/6
# @Desc  :

import os
from enum import Enum

from django.conf import settings

# 目录信息

MODULE_DATA_DIR = os.path.join(settings.BASE_DIR, 'MODULES_DATA')

HANDLER_OPTION = {
    'name': '_msgrpc_handler',

    'tag_zh': '监听',
    'desc_zh': '模块需要的监听器',

    'tag_en': 'Handler',
    'desc_en': 'Handler config that use by module',

    'type': 'enum',
    'option_length': 24
}

CACHE_HANDLER_OPTION = {
    'name': 'cacheHandler',

    'tag_zh': "缓存监听",
    'desc_zh': "模块执行成功后,缓存对应监听配置",

    'tag_en': "Cache Handler",
    'desc_en': "After the module is successfully executed, cache the handler configuration",

    'type': 'bool',
    'default': False,
    "required": True,
}

CREDENTIAL_OPTION = {
    'name': '_postmodule_credential',

    'tag_zh': '凭证',
    'desc_zh': '模块需要的凭证参数',

    'tag_en': 'Credential',
    'desc_en': 'Credential parameters required by the module',

    'type': 'enum',
    'option_length': 24
}

FILE_OPTION = {
    'name': '_postmodule_file',

    'tag_zh': '文件',
    'desc_zh': '模块需要的文件,可以通过<文件管理>上传',

    'tag_en': 'File',
    'desc_en': 'File needed for module can be uploaded through <Files>',

    'type': 'enum',
    'option_length': 24
}


class BROKER(object):
    empty = 'empty'
    post_python_job = 'post_python_job'
    post_msf_job = 'post_msf_job'
    bot_msf_module = 'bot_msf_module'
    bot_python_module = 'bot_python_module'
    proxy_http_scan_module = 'proxy_http_scan_module'


class TAG2TYPE(object):
    """
    模块分类标识
    """
    example = 'example'  # '样例模块',
    internal = 'internal'  # 内部模块(不提供可视化输出,用于内部的模块)

    # 代理扫描模块
    Proxy_Http_Scan = "Proxy_Http_Scan"  # 基于msf的扫描模块

    # 全网扫描类型模块
    Bot_MSF_Scan = "Bot_MSF_Scan"  # 基于msf的扫描模块
    Bot_MSF_Exp = "Bot_MSF_Exp"  # 基于msf的攻击模块
    Bot_PY_Scan = "Bot_PY_Scan"  # python原生扫描模块
    Bot_PY_Exp = "Bot_PY_Exp"  # python原生攻击模块

    # 内网渗透类模块
    Reconnaissance = 'Reconnaissance'  # '前期侦查'
    Resource_Development = 'Resource_Development'  # '资源部署'
    Initial_Access = 'Initial_Access'  # '初始访问'
    Execution = 'Execution'  # '执行'
    Persistence = 'Persistence'  # '持久化',
    Privilege_Escalation = 'Privilege_Escalation'  # '权限提升'
    Defense_Evasion = 'Defense_Evasion'  # '防御绕过'
    Credential_Access = 'Credential_Access'  # '凭证访问'
    Discovery = 'Discovery'  # '信息收集'
    Lateral_Movement = 'Lateral_Movement'  # '横向移动'
    Collection = 'Collection'  # '数据采集'
    Command_and_Control = 'Command_and_Control'  # '命令控制'
    Exfiltration = 'Exfiltration'  # '数据窃取'
    Impact = 'Impact'  # '影响破坏'

    @staticmethod
    def get_moduletype_order(module_type):
        order_dict = {
            "example": 0,
            "internal": 1,
            "Initial_Access": 10,
            "Execution": 11,
            "Persistence": 12,
            "Privilege_Escalation": 13,
            "Defense_Evasion": 14,
            "Credential_Access": 15,
            "Discovery": 16,
            "Lateral_Movement": 17,
            "Collection": 18,
            "Command_and_Control": 19,
            "Exfiltration": 20,
            "Impact": 21,
        }
        order = order_dict.get(module_type)
        if order is not None:
            return order
        else:
            return 100


class UACLevel(Enum):
    UAC_NO_PROMPT = 0
    UAC_PROMPT_CREDS_IF_SECURE_DESKTOP = 1
    UAC_PROMPT_CONSENT_IF_SECURE_DESKTOP = 2
    UAC_PROMPT_CREDS = 3
    UAC_PROMPT_CONSENT = 4
    UAC_DEFAULT = 5


class RegType(Enum):
    REG_NONE = 0
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_BINARY = 3
    REG_DWORD = 4
    REG_DWORD_LITTLE_ENDIAN = 4
    REG_DWORD_BIG_ENDIAN = 5
    REG_LINK = 6
    REG_MULTI_SZ = 7
