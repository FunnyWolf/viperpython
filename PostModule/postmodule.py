# -*- coding: utf-8 -*-
# @File  : postmodule.py
# @Date  : 2019/1/11
# @Desc  :


import importlib
import json
import os
import time
import uuid

from django.conf import settings

from Core.configs import CODE_MSG, PostModuleConfig_MSG, PostModuleActuator_MSG, PostModuleResultHistory_MSG
from Core.core import Host
from Core.lib import logger, dict_data_return, Xcache, list_data_return, Notices
from Msgrpc.msgrpc import MSFModule, Handler, FileMsf, FileSession, aps_module
from PostLateral.postlateral import Credential
from PostModule.lib.Configs import TAG2CH, HANDLER_OPTION, CREDENTIAL_OPTION, FILE_OPTION, BROKER


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
            context = list_data_return(200, CODE_MSG.get(200), all_modules_config)
            return context
        else:
            for one_module_config in all_modules_config:
                if one_module_config.get('loadpath') == loadpath:
                    # 动态处理handler和凭证选项
                    new_module_config = PostModuleConfig._deal_dynamic_option(one_module_config=one_module_config)
                    context = dict_data_return(200, CODE_MSG.get(200), new_module_config)
                    return context
            # 没有找到模块
            context = dict_data_return(200, CODE_MSG.get(200), {})
            return context

    @staticmethod
    def update():
        PostModuleConfig.load_all_modules_config()
        all_modules_config = Xcache.list_moduleconfigs()
        for one in all_modules_config:
            one['OPTIONS'] = []
        context = list_data_return(201, PostModuleConfig_MSG.get(201), all_modules_config)
        return context

    @staticmethod
    def load_all_modules_config():
        def _sort_by_moduletype(module_config=None):
            return TAG2CH.get_moduletype_order(module_config.get('MODULETYPE'))

        all_modules_config = []
        # viper 内置模块
        viper_module_count = 0
        modulenames = os.listdir(os.path.join(settings.BASE_DIR, 'MODULES'))
        for modulename in modulenames:
            modulename = modulename.split(".")[0]
            if modulename == "__init__" or modulename == "__pycache__":  # __init__.py的特殊处理
                continue

            class_intent = importlib.import_module('MODULES.{}'.format(modulename))

            try:
                if isinstance(class_intent.PostModule.ATTCK, str):
                    attck = [class_intent.PostModule.ATTCK]
                elif isinstance(class_intent.PostModule.ATTCK, list):
                    attck = [class_intent.PostModule.ATTCK]
                else:
                    attck = []

                one_module_config = {

                    "BROKER": class_intent.PostModule.MODULE_BROKER,  # 处理器

                    "NAME": class_intent.PostModule.NAME,
                    "DESC": class_intent.PostModule.DESC,
                    "WARN": class_intent.PostModule.WARN,
                    "AUTHOR": class_intent.PostModule.AUTHOR,
                    "REFERENCES": class_intent.PostModule.REFERENCES,

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
        Notices.send_success(f"内置模块加载完成,加载{viper_module_count}个模块")
        # 自定义模块
        diy_module_count = 0
        modulenames = os.listdir(os.path.join(settings.BASE_DIR, 'Docker', "module"))
        for modulename in modulenames:
            modulename = modulename.split(".")[0]
            if modulename == "__init__" or modulename == "__pycache__":  # __init__.py的特殊处理
                continue

            class_intent = importlib.import_module('Docker.module.{}'.format(modulename))
            importlib.reload(class_intent)
            try:
                if isinstance(class_intent.PostModule.ATTCK, str):
                    attck = [class_intent.PostModule.ATTCK]
                elif isinstance(class_intent.PostModule.ATTCK, list):
                    attck = [class_intent.PostModule.ATTCK]
                else:
                    attck = []

                one_module_config = {

                    "BROKER": class_intent.PostModule.MODULE_BROKER,  # 处理器

                    "NAME": class_intent.PostModule.NAME,
                    "DESC": class_intent.PostModule.DESC,
                    "WARN": class_intent.PostModule.WARN,
                    "AUTHOR": class_intent.PostModule.AUTHOR,
                    "REFERENCES": class_intent.PostModule.REFERENCES,

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
        Notices.send_success(f"自定义模块加载完成,加载{diy_module_count}个模块")
        all_modules_config.sort(key=_sort_by_moduletype)
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
                handlers = Handler.list_handler()
                tmp_enum_list = []
                for handler in handlers:
                    import json
                    lhost_str = ""
                    rhost_srt = ""

                    if handler.get('LHOST') is None:
                        try:
                            handler.pop('LHOST')
                        except Exception as _:
                            pass

                    else:
                        lhost_str = "LHOST:{} | ".format(handler.get('LHOST'))

                    if handler.get('RHOST') is None:
                        try:
                            handler.pop('RHOST')
                        except Exception as _:
                            pass
                    else:
                        rhost_srt = "RHOST:{} | ".format(handler.get('RHOST'))

                    # 虚拟监听与真实监听标签
                    if handler.get("ID") < 0:
                        handlertag = "虚拟 | "
                    else:
                        handlertag = ""

                    if handler.get("HandlerName") is None:
                        name = f"{handlertag}{handler.get('PAYLOAD')} | {lhost_str}{rhost_srt} LPORT:{handler.get('LPORT')}"
                    else:
                        name = f"{handlertag}{handler.get('HandlerName')} | {handler.get('PAYLOAD')} | {lhost_str}{rhost_srt} LPORT:{handler.get('LPORT')}"

                    value = json.dumps(handler)
                    tmp_enum_list.append({'name': name, 'value': value})

                option['enum_list'] = tmp_enum_list

                if len(tmp_enum_list) == 1:  # 只有一个监听
                    option['default'] = tmp_enum_list[0].get("value")

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


class PostModuleActuator(object):
    """任务添加器"""

    def __init__(self):
        pass

    @staticmethod
    def create_post(loadpath=None, sessionid=None, hid=None, custom_param=None):
        module_config = Xcache.get_moduleconfig(loadpath)
        # 获取模块配置
        if module_config is None:
            context = dict_data_return(305, PostModuleActuator_MSG.get(305), {})
            return context

        # 处理模块参数
        try:
            custom_param = json.loads(custom_param)
        except Exception as E:
            logger.warning(E)
            custom_param = {}
        # 获取模块实例
        class_intent = importlib.import_module(loadpath)
        post_module_intent = class_intent.PostModule(sessionid, hid, custom_param)

        # 模块前序检查,调用check函数
        try:
            flag, msg = post_module_intent.check()
            if flag is not True:
                # 如果检查未通过,返回未通过原因(msg)
                context = dict_data_return(405, msg, {})
                return context
        except Exception as E:
            logger.warning(E)
            context = dict_data_return(301, PostModuleActuator_MSG.get(301), {})
            return context

        try:
            broker = post_module_intent.MODULE_BROKER
        except Exception as E:
            logger.warning(E)
            context = dict_data_return(305, PostModuleActuator_MSG.get(305), {})
            return context

        if broker == BROKER.post_python_job:
            # 放入多模块队列
            if aps_module.putin_post_python_module_queue(post_module_intent):
                context = dict_data_return(201, PostModuleActuator_MSG.get(201), {})
                return context
            else:
                context = dict_data_return(306, PostModuleActuator_MSG.get(306), {})
                return context
        elif broker == BROKER.post_msf_job:
            # 放入后台运行队列
            if MSFModule.putin_post_msf_module_queue(post_module_intent):
                context = dict_data_return(201, PostModuleActuator_MSG.get(201), {})
                return context
            else:
                context = dict_data_return(306, PostModuleActuator_MSG.get(306), {})
                return context
        else:
            logger.warning("错误的broker")

    @staticmethod
    def create_bot(ipportlist=None, custom_param=None, loadpath=None):
        module_config = Xcache.get_moduleconfig(loadpath)
        # 获取模块配置
        if module_config is None:
            context = dict_data_return(305, PostModuleActuator_MSG.get(305), {})
            return context

        # 处理模块参数
        try:
            custom_param = json.loads(custom_param)
        except Exception as E:
            logger.warning(E)
            custom_param = {}

        # 获取模块实例
        group_uuid = str(uuid.uuid1()).replace('-', "")
        class_intent = importlib.import_module(loadpath)
        for ipport in ipportlist:
            post_module_intent = class_intent.PostModule(ip=ipport.get("ip"), port=ipport.get("port"),
                                                         protocol=ipport.get("protocol"),
                                                         custom_param=custom_param)

            # 模块前序检查,调用check函数
            try:
                flag, msg = post_module_intent.check()
                if flag is not True:
                    # 如果检查未通过,返回未通过原因(msg)
                    Notices.send_warning(f"模块:{post_module_intent.NAME} IP:{ipport.get('ip')} 检查未通过,原因:{msg}")
                    continue

            except Exception as E:
                logger.warning(E)
                Notices.send_warning(f"模块:{post_module_intent.NAME} IP:{ipport.get('ip')} 检查函数执行异常")
                continue

            tmp_self_uuid = str(uuid.uuid1())
            req = {
                'uuid': tmp_self_uuid,
                'group_uuid': group_uuid,
                'broker': post_module_intent.MODULE_BROKER,
                'module': post_module_intent,
                'time': int(time.time()),
            }
            Xcache.putin_bot_wait(req)

        context = dict_data_return(201, PostModuleActuator_MSG.get(201), {})
        return context


class PostModuleResult(object):
    def __init__(self):
        pass

    @staticmethod
    def list(hid=None, loadpath=None):
        host = Host.get_by_hid(hid)
        result = Xcache.get_module_result(ipaddress=host.get("ipaddress"), loadpath=loadpath)
        result_dict = {"hid": hid,
                       "loadpath": loadpath,
                       "update_time": result.get("update_time"),
                       "result": result.get("result")}

        context = dict_data_return(200, CODE_MSG.get(200), result_dict)
        return context


class PostModuleResultHistory(object):
    def __init__(self):
        pass

    @staticmethod
    def list_all():
        try:
            result = Xcache.list_module_result_history()
            for one in result:
                loadpath = one.get("loadpath")
                moduleconfig = Xcache.get_moduleconfig(loadpath)
                if moduleconfig is None:
                    continue
                one["module_name"] = moduleconfig.get("NAME")
            return result
        except Exception as E:
            logger.exception(E)
            return []

    @staticmethod
    def destory():
        Xcache.del_module_result_history()
        context = dict_data_return(204, PostModuleResultHistory_MSG.get(204), {})
        return context
