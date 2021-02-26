# -*- coding: utf-8 -*-
# @File  : setting.py
# @Date  : 2021/2/25
# @Desc  :
import json
import socket

from Lib.External.dingding import DingDing
from Lib.External.fofaclient import FOFAClient
from Lib.External.serverchan import ServerChan
from Lib.External.telegram import Telegram
from Lib.api import data_return
from Lib.configs import Setting_MSG, CODE_MSG
from Lib.log import logger
from Lib.notice import Notice
from Lib.xcache import Xcache
from Msgrpc.Handle.filemsf import FileMsf


class Settings(object):
    def __init__(self):
        pass

    @staticmethod
    def list(kind=None):

        if kind == "lhost":
            # 获取pem秘钥文件,用于https监听配置
            files = FileMsf.list_msf_files()
            pem_files = []
            for file in files:
                name = file.get("name")
                if name.lower().endswith(".pem"):
                    pem_files.append(name)

            conf = Xcache.get_lhost_config()
            if conf is None:
                conf = {'lhost': None, "pem_files": pem_files}
            else:
                conf["pem_files"] = pem_files

        elif kind == "telegram":
            conf = Xcache.get_telegram_conf()
            if conf is None:
                conf = {"token": "", "chat_id": [], "proxy": "", "alive": False}

        elif kind == "dingding":
            conf = Xcache.get_dingding_conf()
            if conf is None:
                conf = {"access_token": "", "keyword": "", "alive": False}
        elif kind == "serverchan":
            conf = Xcache.get_serverchan_conf()
            if conf is None:
                conf = {"sendkey": "", "alive": False}
        elif kind == "FOFA":
            conf = Xcache.get_fofa_conf()
            if conf is None:
                conf = {"email": "", "key": "", "alive": False}
        elif kind == "sessionmonitor":
            conf = Xcache.get_sessionmonitor_conf()
        else:
            context = data_return(301, Setting_MSG.get(301), {})
            return context

        context = data_return(200, CODE_MSG.get(200), conf)
        return context

    @staticmethod
    def get_lhost():
        conf = Xcache.get_lhost_config()
        if conf is None:
            return None
        else:
            return conf.get("lhost")

    @staticmethod
    def is_empty_ports(useport=None):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("0.0.0.0", useport))
            sock.close()
            return True
        except socket.error:
            logger.warning(f"端口: {useport},已占用")
            return False

    @staticmethod
    def create(kind=None, tag=None, setting=None):
        """创建系统配置"""
        if isinstance(setting, str):
            setting = json.loads(setting)

        if kind == "telegram":
            token = setting.get("token")
            chat_id = setting.get("chat_id")
            proxy = setting.get("proxy")
            if tag == "check":  # 获取chat_id
                user_chat_id_list = Telegram.get_alive_chat_id(token, proxy)
                context = data_return(201, Setting_MSG.get(201), user_chat_id_list)
                return context
            else:
                if Settings._check_telegram_aliveable(token, chat_id, proxy) is not True:
                    data = {"token": token, "chat_id": chat_id, "proxy": proxy, "alive": False}
                    Xcache.set_telegram_conf(data)
                    context = data_return(303, Setting_MSG.get(303), data)
                    return context
                else:
                    Notice.send_success("设置Telegram通知成功")
                    data = {"token": token, "chat_id": chat_id, "proxy": proxy, "alive": True}
                    Xcache.set_telegram_conf(data)
                    context = data_return(202, Setting_MSG.get(202), data)
                    return context

        elif kind == "dingding":
            access_token = setting.get("access_token")
            keyword = setting.get("keyword")

            if Settings._check_dingding_aliveable(access_token, keyword) is not True:
                data = {"access_token": access_token, "keyword": keyword, "alive": False}
                Xcache.set_dingding_conf(data)
                context = data_return(304, Setting_MSG.get(304), data)
                return context
            else:
                Notice.send_success("设置DingDing通知成功")
                data = {"access_token": access_token, "keyword": keyword, "alive": True}
                Xcache.set_dingding_conf(data)

                context = data_return(203, Setting_MSG.get(203), data)
                return context
        elif kind == "serverchan":
            sendkey = setting.get("sendkey")
            if Settings._check_serverchan_aliveable(sendkey) is not True:
                data = {"sendkey": sendkey, "alive": False}
                Xcache.set_serverchan_conf(data)
                context = data_return(305, Setting_MSG.get(305), data)
                return context
            else:
                Notice.send_success("设置Server酱通知成功")
                data = {"sendkey": sendkey, "alive": True}
                Xcache.set_serverchan_conf(data)

                context = data_return(207, Setting_MSG.get(207), data)
                return context

        elif kind == "FOFA":
            email = setting.get("email")
            key = setting.get("key")
            client = FOFAClient()
            client.set_email_and_key(email, key)
            if client.is_alive() is not True:
                data = {"email": email, "key": key, "alive": False}
                Xcache.set_fofa_conf(data)
                context = data_return(306, Setting_MSG.get(306), data)
                return context
            else:
                Notice.send_success("设置FOFA API 成功")
                data = {"email": email, "key": key, "alive": True}
                Xcache.set_fofa_conf(data)
                context = data_return(206, Setting_MSG.get(206), data)
                return context

        elif kind == "sessionmonitor":
            flag = setting.get("flag")
            Xcache.set_sessionmonitor_conf({"flag": flag})

            if flag:
                msg = "Session监控功能已打开"
                Notice.send_success(msg)
                Notice.send_sms(msg)
            else:
                msg = "Session监控功能已关闭"
                Notice.send_info(msg)
                Notice.send_sms(msg)

            context = data_return(204, Setting_MSG.get(204), {"flag": flag})
            return context

        elif kind == "lhost":
            Xcache.set_lhost_config(setting)
            Notice.send_success(f"设置回连地址成功,当前回连地址: {setting.get('lhost')}")
            context = data_return(205, Setting_MSG.get(205), setting)
            return context
        else:
            context = data_return(301, Setting_MSG.get(301), {})
            return context

    @staticmethod
    def _check_telegram_aliveable(token=None, chat_id=None, proxy=None):
        msg = "此消息为测试消息,Viper已加入通知bot"
        send_result = Settings.send_telegram_message(msg, {"token": token, "chat_id": chat_id, "proxy": proxy,
                                                           "alive": True})
        if len(send_result) > 0:
            return True
        else:
            return False

    @staticmethod
    def _check_dingding_aliveable(access_token=None, keyword=None):
        msg = "此消息为测试消息,Viper已加入通知bot"
        result = Settings.send_dingding_message(msg,
                                                {"access_token": access_token, "keyword": keyword, "alive": True})
        return result

    @staticmethod
    def _check_serverchan_aliveable(sendkey=None):
        msg = "此消息为测试消息,Viper已加入通知bot"
        result = Settings.send_serverchan_message(msg, {"sendkey": sendkey, "alive": True})
        return result

    @staticmethod
    def send_telegram_message(msg=None, conf=None):
        if conf is None:
            conf = Xcache.get_telegram_conf()
        if conf is None:
            return []

        if conf.get("alive"):
            pass
        else:
            return []

        send_result = Telegram.send_text(token=conf.get("token"), chat_id=conf.get("chat_id"), proxy=conf.get("proxy"),
                                         msg=msg)
        return send_result

    @staticmethod
    def send_dingding_message(msg=None, conf=None):
        if conf is None:
            conf = Xcache.get_dingding_conf()
        if conf is None:
            return False
        if conf.get("alive"):
            pass
        else:
            return False
        access_token = conf.get("access_token")
        keyword = conf.get("keyword")
        try:
            ding = DingDing(access_token)
            result = ding.send_text(msg, keyword=keyword)
            if result.get("errcode") == 0:
                return True
            else:
                return False
        except Exception as E:
            logger.warning(E)
            return False

    @staticmethod
    def send_serverchan_message(msg=None, conf=None):
        if conf is None:
            conf = Xcache.get_serverchan_conf()
        if conf is None:
            return False
        if conf.get("alive"):
            pass
        else:
            return False
        sendkey = conf.get("sendkey")
        serverchan = ServerChan(sendkey=sendkey)
        try:
            result = serverchan.send_text(msg)
            return result
        except Exception as E:
            logger.warning(E)
            return False

    @staticmethod
    def _send_bot_msg(message=None):

        content = message.get('data')
        flag = False
        send_result = Settings.send_telegram_message(content)
        if len(send_result) > 0:
            flag = True
        send_result = Settings.send_dingding_message(content)
        if send_result is True:
            flag = True
        send_result = Settings.send_serverchan_message(content)
        if send_result is True:
            flag = True
        return flag
