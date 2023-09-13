# -*- coding: utf-8 -*-
# @File  : postmoduleconfig.py
# @Date  : 2021/2/26
# @Desc  :
import importlib
import os
import time

from django.conf import settings

from Lib.Module.configs import TAG2TYPE, HANDLER_OPTION, CREDENTIAL_OPTION, FILE_OPTION
from Lib.api import data_return
from Lib.configs import CODE_MSG_ZH, PostModuleConfig_MSG_ZH, CODE_MSG_EN, PostModuleConfig_MSG_EN, VIPER_IP
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
            if one.get('MODULETYPE') == TAG2TYPE.internal:
                all_modules_config.remove(one)

        if loadpath is None:
            context = data_return(200, all_modules_config, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
            return context
        else:
            for one_module_config in all_modules_config:
                if one_module_config.get('loadpath') == loadpath:
                    # 动态处理handler和凭证选项
                    new_module_config = PostModuleConfig._deal_dynamic_option(one_module_config=one_module_config)
                    context = data_return(200, new_module_config, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
                    return context
            # 没有找到模块
            context = data_return(200, {}, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
            return context

    @staticmethod
    def list_dynamic_option():
        all_modules_config = Xcache.list_moduleconfigs()
        if all_modules_config is None:
            PostModuleConfig.load_all_modules_config()
            all_modules_config = Xcache.list_moduleconfigs()

        # 删除内部模块
        for one in all_modules_config[:]:
            if one.get('MODULETYPE') == TAG2TYPE.internal:
                all_modules_config.remove(one)
        # 准备数据
        handlers = Handler.list_handler_config()
        credentials = Credential.list_credential()
        files = FileMsf.list_msf_files()

        for one_module_config in all_modules_config:
            options = one_module_config['OPTIONS']
            for option in options:
                # handler处理
                if option.get('name') == HANDLER_OPTION.get("name"):
                    option['enum_list'] = handlers
                    if len(option['enum_list']) == 1:  # 只有一个监听
                        option['default'] = option['enum_list'][0].get("value")

                # 凭证处理
                elif option.get('name') == CREDENTIAL_OPTION.get("name"):
                    tmp_enum_list = []
                    try:
                        if option.get('extra_data') is None or option.get('extra_data').get('password_type') is None:
                            pass
                        else:
                            type_list = option.get('extra_data').get('password_type')
                            for credential in credentials:
                                if credential.get('password_type') in type_list:
                                    tag_zh = f"用户: {credential.get('username')}  密码: {credential.get('password')}  标签: {credential.get('tag')}"
                                    tag_en = f"User: {credential.get('username')}  Password: {credential.get('password')}  Tag: {credential.get('tag')}"
                                    import json
                                    value = json.dumps(credential)
                                    tmp_enum_list.append({'tag_zh': tag_zh, 'tag_en': tag_en, 'value': value})
                        option['enum_list'] = tmp_enum_list
                    except Exception as E:
                        logger.warning(E)

                # 文件处理
                elif option.get('name') == FILE_OPTION.get("name"):
                    if option.get('extra_data') is None or option.get('extra_data').get('file_extension') is None:
                        file_extension_list = None
                    else:
                        file_extension_list = option.get('extra_data').get('file_extension')

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
                            tag_zh = f"文件: {name}\t\t大小: {size}\t\t修改时间: {style_time}"
                            tag_en = f"File: {name}\t\tSize: {size}\t\tMTime: {style_time}"
                            value = json.dumps(file)
                            tmp_enum_list.append({'tag_zh': tag_zh, 'tag_en': tag_en, 'value': value})
                    option['enum_list'] = tmp_enum_list

        return all_modules_config

    @staticmethod
    def update():
        PostModuleConfig.load_all_modules_config()
        all_modules_config = Xcache.list_moduleconfigs()
        # 删除内部模块
        for one in all_modules_config[:]:
            if one.get('MODULETYPE') == TAG2TYPE.internal:
                all_modules_config.remove(one)
        for one in all_modules_config:
            one['OPTIONS'] = []
        context = data_return(201, all_modules_config, PostModuleConfig_MSG_ZH.get(201),
                              PostModuleConfig_MSG_EN.get(201))
        return context

    @staticmethod
    def get_one_module_config(modulename, module_files_dir="MODULES"):
        modulename = modulename.split(".")[0]
        if modulename == "__init__" or modulename == "__pycache__":  # __init__.py的特殊处理
            return None
        try:
            class_intent = importlib.import_module(f'{module_files_dir}.{modulename}')
            module_intent = class_intent.PostModule
        except Exception as E:
            logger.exception(E)
            Notice.send_warning(f"加载模块:{module_files_dir}.{modulename} 失败",
                                f"Load module:{module_files_dir}.{modulename} failed")
            return None

        try:
            if isinstance(module_intent.ATTCK, str):
                attck = [module_intent.ATTCK]
            elif isinstance(module_intent.ATTCK, list):
                attck = module_intent.ATTCK
            else:
                attck = []

            if isinstance(module_intent.AUTHOR, str):
                author = [module_intent.AUTHOR]
            elif isinstance(module_intent.AUTHOR, list):
                author = module_intent.AUTHOR
            else:
                author = []

            one_module_config = {

                "BROKER": module_intent.MODULE_BROKER,  # 处理器

                "NAME_ZH": module_intent.NAME_ZH,
                "DESC_ZH": module_intent.DESC_ZH,
                "NAME_EN": module_intent.NAME_EN,
                "DESC_EN": module_intent.DESC_EN,
                "WARN_ZH": module_intent.WARN_ZH,
                "WARN_EN": module_intent.WARN_EN,
                "AUTHOR": author,
                "REFERENCES": module_intent.REFERENCES,
                "README": module_intent.README,

                "MODULETYPE": module_intent.MODULETYPE,

                "OPTIONS": module_intent.OPTIONS,
                "loadpath": f'MODULES.{modulename}',

                # post类配置
                "REQUIRE_SESSION": module_intent.REQUIRE_SESSION,
                "PLATFORM": module_intent.PLATFORM,
                "PERMISSIONS": module_intent.PERMISSIONS,
                "ATTCK": attck,

                # bot类配置
                "SEARCH": module_intent.SEARCH,

            }
            return one_module_config
        except Exception as E:
            logger.error(E)
            return None

    @staticmethod
    def load_all_modules_config():
        all_modules_config = []
        # viper 内置模块
        viper_module_count = 0
        modulenames = os.listdir(os.path.join(settings.BASE_DIR, 'MODULES'))
        for modulename in modulenames:
            one_module_config = PostModuleConfig.get_one_module_config(modulename, 'MODULES')
            if one_module_config is not None:
                all_modules_config.append(one_module_config)
                viper_module_count += 1
        logger.warning(f"内置模块加载完成,加载{viper_module_count}个模块")
        Notice.send_info(f"内置模块加载完成,加载{viper_module_count}个模块",
                         f"The built-in modules is loaded, {viper_module_count} modules has loaded")

        # 自定义模块
        diy_module_count = 0
        modulenames = os.listdir(os.path.join(settings.BASE_DIR, 'Docker', "module"))
        for modulename in modulenames:
            one_module_config = PostModuleConfig.get_one_module_config(modulename, 'Docker.module')
            if one_module_config is not None:
                all_modules_config.append(one_module_config)
                diy_module_count += 1
        logger.warning(f"自定义模块加载完成,加载{diy_module_count}个模块")
        Notice.send_info(f"自定义模块加载完成,加载{diy_module_count}个模块",
                         f"The customize modules is loaded, {diy_module_count} modules has loaded")

        all_modules_config.sort(key=lambda s: (TAG2TYPE.get_moduletype_order(s.get('MODULETYPE')), s.get('loadpath')))
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
                                tag_zh = f"用户: {credential.get('username')}  密码: {credential.get('password')}  标签: {credential.get('tag')}"
                                tag_en = f"User: {credential.get('username')}  Password: {credential.get('password')}  Tag: {credential.get('tag')}"
                                import json
                                value = json.dumps(credential)
                                tmp_enum_list.append({'tag_zh': tag_zh, 'tag_en': tag_en, 'value': value})
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
                        tag_zh = f"文件: {name}\t\t大小: {size}\t\t修改时间: {style_time}"
                        tag_en = f"File: {name}\t\tSize: {size}\t\tMTime: {style_time}"
                        value = json.dumps(file)
                        tmp_enum_list.append({'tag_zh': tag_zh, 'tag_en': tag_en, 'value': value})
                option['enum_list'] = tmp_enum_list
        return one_module_config

    @staticmethod
    def get_module_name_by_loadpath(loadpath=None):
        module_config = Xcache.get_moduleconfig(loadpath)
        if module_config is not None:
            return f"{module_config.get('NAME_EN')}"
        else:
            return None

    @staticmethod
    def get_post_module_intent(loadpath, sessionid=-1, ipaddress=VIPER_IP, custom_param=None):
        """获取一个模块实例"""
        if custom_param is None:
            custom_param = {}
        try:
            class_intent = importlib.import_module(loadpath)
            post_module_intent = class_intent.PostModule(sessionid, ipaddress, custom_param)
            return post_module_intent
        except Exception as E:
            logger.exception(E)
            return None
