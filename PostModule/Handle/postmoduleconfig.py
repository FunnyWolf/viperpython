# -*- coding: utf-8 -*-
# @File  : postmoduleconfig.py
# @Date  : 2021/2/26
# @Desc  :
import importlib
import os
import time

from django.conf import settings

from Lib.Module.configs import TAG2CH, HANDLER_OPTION, CREDENTIAL_OPTION, FILE_OPTION
from Lib.api import data_return
from Lib.configs import CODE_MSG, PostModuleConfig_MSG
from Lib.log import logger
from Lib.notice import Notice
from Lib.xcache import Xcache
from Msgrpc.Handle.filemsf import FileMsf
from Msgrpc.Handle.filesession import FileSession
from Msgrpc.Handle.handler import Handler
from PostLateral.Handle.credential import Credential


class PostModuleConfig(object):
    def __init__(self):
        pass

    @staticmethod
    def list(loadpath=None):
        all_modules_config = Xcache.list_moduleconfigs()
        if all_modules_config is None:
            PostModuleConfig.load_all_modules_config()
            all_modules_config = Xcache.list_moduleconfigs()

        # 删除内部模块
        for one in all_modules_config[:]:
            if one.get('MODULETYPE') == TAG2CH.internal:
                all_modules_config.remove(one)

        if loadpath is None:
            for one in all_modules_config:
                one['OPTIONS'] = []
            context = data_return(200, CODE_MSG.get(200), all_modules_config)
            return context
        else:
            for one_module_config in all_modules_config:
                if one_module_config.get('loadpath') == loadpath:
                    # 动态处理handler和凭证选项
                    new_module_config = PostModuleConfig._deal_dynamic_option(one_module_config=one_module_config)
                    context = data_return(200, CODE_MSG.get(200), new_module_config)
                    return context
            # 没有找到模块
            context = data_return(200, CODE_MSG.get(200), {})
            return context

    @staticmethod
    def update():
        PostModuleConfig.load_all_modules_config()
        all_modules_config = Xcache.list_moduleconfigs()
        # 删除内部模块
        for one in all_modules_config[:]:
            if one.get('MODULETYPE') == TAG2CH.internal:
                all_modules_config.remove(one)
        for one in all_modules_config:
            one['OPTIONS'] = []
        context = data_return(201, PostModuleConfig_MSG.get(201), all_modules_config)
        return context

    @staticmethod
    def load_all_modules_config():
        all_modules_config = []
        # viper 内置模块
        viper_module_count = 0
        modulenames = os.listdir(os.path.join(settings.BASE_DIR, 'MODULES'))
        for modulename in modulenames:
            modulename = modulename.split(".")[0]
            if modulename == "__init__" or modulename == "__pycache__":  # __init__.py的特殊处理
                continue

            class_intent = importlib.import_module(f'MODULES.{modulename}')

            try:
                if isinstance(class_intent.PostModule.ATTCK, str):
                    attck = [class_intent.PostModule.ATTCK]
                elif isinstance(class_intent.PostModule.ATTCK, list):
                    attck = class_intent.PostModule.ATTCK
                else:
                    attck = []

                if isinstance(class_intent.PostModule.AUTHOR, str):
                    author = [class_intent.PostModule.AUTHOR]
                elif isinstance(class_intent.PostModule.AUTHOR, list):
                    author = class_intent.PostModule.AUTHOR
                else:
                    author = []

                one_module_config = {

                    "BROKER": class_intent.PostModule.MODULE_BROKER,  # 处理器

                    "NAME": class_intent.PostModule.NAME,
                    "DESC": class_intent.PostModule.DESC,
                    "WARN": class_intent.PostModule.WARN,
                    "AUTHOR": author,
                    "REFERENCES": class_intent.PostModule.REFERENCES,
                    "README": class_intent.PostModule.README,

                    "MODULETYPE": class_intent.PostModule.MODULETYPE,

                    "OPTIONS": class_intent.PostModule.OPTIONS,
                    "loadpath": 'MODULES.{}'.format(modulename),

                    # post类配置
                    "REQUIRE_SESSION": class_intent.PostModule.REQUIRE_SESSION,
                    "PLATFORM": class_intent.PostModule.PLATFORM,
                    "PERMISSIONS": class_intent.PostModule.PERMISSIONS,
                    "ATTCK": attck,

                    # bot类配置
                    "SEARCH": class_intent.PostModule.SEARCH,

                }
                all_modules_config.append(one_module_config)
                viper_module_count += 1
            except Exception as E:
                logger.error(E)
                continue
        logger.warning("内置模块加载完成,加载{}个模块".format(viper_module_count))
        Notice.send_success(f"内置模块加载完成,加载{viper_module_count}个模块")
        # 自定义模块
        diy_module_count = 0
        modulenames = os.listdir(os.path.join(settings.BASE_DIR, 'Docker', "module"))
        for modulename in modulenames:
            modulename = modulename.split(".")[0]
            if modulename == "__init__" or modulename == "__pycache__":  # __init__.py的特殊处理
                continue
            try:
                class_intent = importlib.import_module('Docker.module.{}'.format(modulename))
                importlib.reload(class_intent)
            except Exception as E:
                logger.exception(E)
                Notice.send_alert(f"加载自定义模块:{modulename} 失败")
                continue
            try:
                if isinstance(class_intent.PostModule.ATTCK, str):
                    attck = [class_intent.PostModule.ATTCK]
                elif isinstance(class_intent.PostModule.ATTCK, list):
                    attck = [class_intent.PostModule.ATTCK]
                else:
                    attck = []

                if isinstance(class_intent.PostModule.AUTHOR, str):
                    author = [class_intent.PostModule.AUTHOR]
                elif isinstance(class_intent.PostModule.AUTHOR, list):
                    author = class_intent.PostModule.AUTHOR
                else:
                    author = []

                one_module_config = {

                    "BROKER": class_intent.PostModule.MODULE_BROKER,  # 处理器

                    "NAME": class_intent.PostModule.NAME,
                    "DESC": class_intent.PostModule.DESC,
                    "WARN": class_intent.PostModule.WARN,
                    "AUTHOR": author,
                    "REFERENCES": class_intent.PostModule.REFERENCES,
                    "README": class_intent.PostModule.README,

                    "MODULETYPE": class_intent.PostModule.MODULETYPE,

                    "OPTIONS": class_intent.PostModule.OPTIONS,
                    "loadpath": 'Docker.module.{}'.format(modulename),

                    # post类配置
                    "REQUIRE_SESSION": class_intent.PostModule.REQUIRE_SESSION,
                    "PLATFORM": class_intent.PostModule.PLATFORM,
                    "PERMISSIONS": class_intent.PostModule.PERMISSIONS,
                    "ATTCK": attck,

                    # bot类配置
                    "SEARCH": class_intent.PostModule.SEARCH,

                }
                all_modules_config.append(one_module_config)
                diy_module_count += 1
            except Exception as E:
                logger.error(E)
                continue
        logger.warning("自定义模块加载完成,加载{}个模块".format(diy_module_count))
        Notice.send_success(f"自定义模块加载完成,加载{diy_module_count}个模块")

        all_modules_config.sort(key=lambda s: (TAG2CH.get_moduletype_order(s.get('MODULETYPE')), s.get('loadpath')))
        if Xcache.update_moduleconfigs(all_modules_config):
            return len(all_modules_config)
        else:
            return 0

    @staticmethod
    def _deal_dynamic_option(one_module_config=None):
        """处理handler及凭证等动态变化参数,返回处理后参数列表"""
        options = one_module_config.get('OPTIONS')
        for option in options:
            # handler处理
            if option.get('name') == HANDLER_OPTION.get("name"):
                option['enum_list'] = Handler.list_handler_config()
                if len(option['enum_list']) == 1:  # 只有一个监听
                    option['default'] = option['enum_list'][0].get("value")

            # 凭证处理
            elif option.get('name') == CREDENTIAL_OPTION.get("name"):
                credentials = Credential.list_credential()
                tmp_enum_list = []
                try:
                    if option.get('extra_data') is None or option.get('extra_data').get('password_type') is None:
                        pass
                    else:
                        type_list = option.get('extra_data').get('password_type')
                        for credential in credentials:
                            if credential.get('password_type') in type_list:
                                name = "用户名:{} | 密码:{} | 标签:{} | 主机:{}".format(credential.get('username'),
                                                                               credential.get('password'),
                                                                               credential.get('tag'),
                                                                               credential.get('host_ipaddress'))
                                import json
                                value = json.dumps(credential)
                                tmp_enum_list.append({'name': name, 'value': value})
                    option['enum_list'] = tmp_enum_list
                except Exception as E:
                    logger.warning(E)
            # 文件处理
            elif option.get('name') == FILE_OPTION.get("name"):
                if option.get('extra_data') is None or option.get('extra_data').get('file_extension') is None:
                    file_extension_list = None
                else:
                    file_extension_list = option.get('extra_data').get('file_extension')

                files = FileMsf.list_msf_files()
                tmp_enum_list = []
                for file in files:
                    import json
                    # {
                    #     "filename": "test",
                    #     "filesize": 0,
                    #     "mtime": 1552273961
                    # },
                    name = file.get("name")
                    size = FileSession.get_size_in_nice_string(file.get('size'))
                    mtime = file.get("mtime")
                    style_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))
                    show = False  # 是否满足文件后缀要求
                    if isinstance(file_extension_list, list):
                        for ext in file_extension_list:
                            if name.lower().endswith(ext.lower()):
                                show = True
                    else:
                        show = True
                    if show:
                        name = "文件: {}   大小: {}   修改时间: {}".format(name, size, style_time)
                        value = json.dumps(file)
                        tmp_enum_list.append({'name': name, 'value': value})
                option['enum_list'] = tmp_enum_list
        return one_module_config

    @staticmethod
    def get_module_name_by_loadpath(loadpath=None):
        module_config = Xcache.get_moduleconfig(loadpath)
        if module_config is not None:
            return module_config.get('NAME')
        else:
            return None
