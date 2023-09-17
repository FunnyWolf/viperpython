# -*- coding: utf-8 -*-
# @File  : setting.py
# @Date  : 2021/2/25
# @Desc  :
import json
import os
from urllib import parse

import chardet
from django.http import HttpResponse

from Lib.External.dingding import DingDing
from Lib.External.fofaclient import FOFAClient
from Lib.External.quake import Quake
from Lib.External.serverchan import ServerChan
from Lib.External.telegram import Telegram
from Lib.External.zoomeyeapi import ZoomeyeAPI
from Lib.api import data_return
from Lib.configs import Setting_MSG_ZH, CODE_MSG_ZH, CODE_MSG_EN, Setting_MSG_EN
from Lib.file import File
from Lib.log import logger
from Lib.notice import Notice
from Lib.xcache import Xcache
from Msgrpc.Handle.filemsf import FileMsf
from Msgrpc.Handle.handler import Handler


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

            lhostconf = Xcache.get_lhost_config()
            session_dict = Xcache.get_session_list()
            conf = {'lhost': lhostconf.get("lhost"), "pem_files": pem_files, "sessions": session_dict}
        elif kind == "telegram":
            conf = Xcache.get_telegram_conf()
        elif kind == "dingding":
            conf = Xcache.get_dingding_conf()
        elif kind == "serverchan":
            conf = Xcache.get_serverchan_conf()
        elif kind == "FOFA":
            conf = Xcache.get_fofa_conf()
        elif kind == "Quake":
            conf = Xcache.get_quake_conf()
        elif kind == "Zoomeye":
            conf = Xcache.get_zoomeye_conf()
        elif kind == "sessionmonitor":
            conf = Xcache.get_sessionmonitor_conf()
        elif kind == "postmoduleautoconf":
            conf = Xcache.get_postmodule_auto_conf()
        elif kind == "proxyhttpscanconf":
            conf = Xcache.get_proxy_http_scan_conf()
        elif kind == "handlerconf":
            conf = Handler.list_handler_config()
        elif kind == "dnslog":
            conf = Xcache.get_dnslog_conf()
        elif kind == "downloadlog":  # 下载日志文件
            zip_file_path = File.zip_logs()
            with open(zip_file_path, "rb+") as f:
                binary_data = f.read()
            os.remove(zip_file_path)
            response = HttpResponse(binary_data)
            response['Content-Type'] = 'application/octet-stream'
            response['Code'] = 200
            response['Msg_zh'] = parse.quote(Setting_MSG_ZH.get(210))
            response['Msg_en'] = parse.quote(Setting_MSG_ZH.get(210))
            response['Content-Disposition'] = os.path.split(zip_file_path)[1]
            return response
        else:
            context = data_return(301, {}, Setting_MSG_ZH.get(301), Setting_MSG_EN.get(301))
            return context
        context = data_return(200, conf, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        return context

    @staticmethod
    def create(kind=None, tag=None, setting=None):
        """创建系统配置"""
        if isinstance(setting, str):
            setting = json.loads(setting)

        if kind == "telegram":
            token = setting.get("token")
            chat_id = setting.get("chat_id")
            proxy = setting.get("proxy")
            if tag == "check":
                # 获取chat_id
                user_chat_id_list = Telegram.get_alive_chat_id(token, proxy)
                context = data_return(201, user_chat_id_list, Setting_MSG_ZH.get(201), Setting_MSG_EN.get(201))
                return context
            else:
                if Settings._check_telegram_aliveable(token, chat_id, proxy) is not True:
                    data = {"token": token, "chat_id": chat_id, "proxy": proxy, "alive": False}
                    Xcache.set_telegram_conf(data)
                    context = data_return(303, data, Setting_MSG_ZH.get(303), Setting_MSG_EN.get(303))
                    return context
                else:
                    Notice.send_info("设置Telegram通知成功", "Set Telegram notification successfully")
                    data = {"token": token, "chat_id": chat_id, "proxy": proxy, "alive": True}
                    Xcache.set_telegram_conf(data)
                    context = data_return(202, data, Setting_MSG_ZH.get(202), Setting_MSG_EN.get(202))
                    return context

        elif kind == "dingding":
            access_token = setting.get("access_token")
            keyword = setting.get("keyword")

            if Settings._check_dingding_aliveable(access_token, keyword) is not True:
                data = {"access_token": access_token, "keyword": keyword, "alive": False}
                Xcache.set_dingding_conf(data)
                context = data_return(304, data, Setting_MSG_ZH.get(304), Setting_MSG_EN.get(304))
                return context
            else:
                Notice.send_info("设置DingDing通知成功", "Set DingDing notification successfully")
                data = {"access_token": access_token, "keyword": keyword, "alive": True}
                Xcache.set_dingding_conf(data)

                context = data_return(203, data, Setting_MSG_ZH.get(203), Setting_MSG_EN.get(203))
                return context

        elif kind == "serverchan":
            sendkey = setting.get("sendkey")
            if Settings._check_serverchan_aliveable(sendkey) is not True:
                data = {"sendkey": sendkey, "alive": False}
                Xcache.set_serverchan_conf(data)
                context = data_return(305, data, Setting_MSG_ZH.get(305), Setting_MSG_EN.get(305))
                return context
            else:
                Notice.send_info("设置Server酱通知成功", "Set ServerChan notification successfully")
                data = {"sendkey": sendkey, "alive": True}
                Xcache.set_serverchan_conf(data)

                context = data_return(207, data, Setting_MSG_ZH.get(207), Setting_MSG_EN.get(207))
                return context

        elif kind == "FOFA":
            email = setting.get("email")
            key = setting.get("key")
            client = FOFAClient()
            client.set_email_and_key(email, key)
            if client.is_alive() is not True:
                data = {"email": email, "key": key, "alive": False}
                Xcache.set_fofa_conf(data)
                context = data_return(306, data, Setting_MSG_ZH.get(306), Setting_MSG_EN.get(306))
                return context
            else:
                Notice.send_info("设置FOFA API成功", "Set FOFA API successfully")
                data = {"email": email, "key": key, "alive": True}
                Xcache.set_fofa_conf(data)
                context = data_return(206, data, Setting_MSG_ZH.get(206), Setting_MSG_EN.get(206))
                return context

        elif kind == "Quake":
            key = setting.get("key").strip()
            client = Quake()
            client.set_key(key)
            if client.is_alive() is not True:
                data = {"key": key, "alive": False}
                Xcache.set_quake_conf(data)
                context = data_return(307, data, Setting_MSG_ZH.get(307), Setting_MSG_EN.get(307))
                return context
            else:
                Notice.send_info("设置360Quake API成功", "Set 360Quake API successfully")
                data = {"key": key, "alive": True}
                Xcache.set_quake_conf(data)
                context = data_return(208, data, Setting_MSG_ZH.get(208), Setting_MSG_EN.get(208))
                return context

        elif kind == "Zoomeye":
            key = setting.get("key").strip()
            client = ZoomeyeAPI()
            client.set_key(key)
            if client.is_alive() is not True:
                data = {"key": key, "alive": False}
                Xcache.set_zoomeye_conf(data)
                context = data_return(308, data, Setting_MSG_ZH.get(308), Setting_MSG_EN.get(308))
                return context
            else:
                Notice.send_info("设置Zoomeye API成功", "Set Zoomeye API successfully")
                data = {"key": key, "alive": True}
                Xcache.set_zoomeye_conf(data)
                context = data_return(212, data, Setting_MSG_ZH.get(212), Setting_MSG_EN.get(212))
                return context

        elif kind == "sessionmonitor":
            flag = setting.get("flag")
            Xcache.set_sessionmonitor_conf({"flag": flag})

            if flag:
                msg = "Session监控功能已打开"
                msg_en = "Session monitor function is turned on"
                Notice.send_info(msg, msg_en)
                Notice.send_sms(msg, msg_en)
            else:
                msg = "Session监控功能已关闭"
                msg_en = "Session monitor function is closed"
                Notice.send_info(msg, msg_en)
                Notice.send_sms(msg, msg_en)

            context = data_return(204, {"flag": flag}, Setting_MSG_ZH.get(204), Setting_MSG_EN.get(204))
            return context

        elif kind == "lhost":
            Xcache.set_lhost_config(setting)
            Notice.send_info(f"设置回连地址成功,当前回连地址: {setting.get('lhost')}",
                             f"Set the lhost successfully, the current lhost: {setting.get('lhost')}")
            context = data_return(205, setting, Setting_MSG_ZH.get(205), Setting_MSG_EN.get(205))
            return context
        elif kind == "dnslog":
            Xcache.set_dnslog_conf(setting)
            Notice.send_info(f"设置DNSLOG成功,当前DNSLOG: {setting.get('dnslog_base')}",
                             f"Set the dnslog successfully, the current dnslog: {setting.get('dnslog_base')}")
            context = data_return(205, setting, Setting_MSG_ZH.get(211), Setting_MSG_EN.get(211))
            return context
        elif kind == "postmoduleautoconf":
            new_conf = Xcache.set_postmodule_auto_conf(setting)
            Notice.send_info(f"设置自动编排配置成功", "Automatic arrangement configuration is set successfully")
            context = data_return(209, new_conf, Setting_MSG_ZH.get(209), Setting_MSG_EN.get(209))
            return context
        elif kind == "proxyhttpscanconf":
            new_conf = Xcache.set_proxy_http_scan_conf(setting)
            Notice.send_info(f"设置被动扫描配置成功", "Passive HTTP Scanning is set successfully")
            context = data_return(211, new_conf, Setting_MSG_ZH.get(211), Setting_MSG_EN.get(211))
            return context
        else:
            context = data_return(301, {}, Setting_MSG_ZH.get(301), Setting_MSG_EN.get(301))
            return context

    @staticmethod
    def _check_telegram_aliveable(token=None, chat_id=None, proxy=None):
        msg = "此消息为测试消息,Viper已加入通知bot.This message is a test message, Viper has joined the notification bot"
        send_result = Settings._send_telegram_message(msg, {"token": token, "chat_id": chat_id, "proxy": proxy,
                                                            "alive": True})
        if len(send_result) > 0:
            return True
        else:
            return False

    @staticmethod
    def _check_dingding_aliveable(access_token=None, keyword=None):
        msg = "此消息为测试消息,Viper已加入通知bot.This message is a test message, Viper has joined the notification bot"
        result = Settings._send_dingding_message(msg,
                                                 {"access_token": access_token, "keyword": keyword, "alive": True})
        return result

    @staticmethod
    def _check_serverchan_aliveable(sendkey=None):
        msg = "此消息为测试消息,Viper已加入通知bot.This message is a test message, Viper has joined the notification bot"
        result = Settings._send_serverchan_message(msg, {"sendkey": sendkey, "alive": True})
        return result

    @staticmethod
    def _send_telegram_message(msg=None, conf=None):
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
    def _send_dingding_message(msg=None, conf=None):
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
    def _send_serverchan_message(msg=None, conf=None):
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
    def send_bot_msg(message=None):
        content = message.get('data')
        chardet_result = chardet.detect(content)
        try:
            data = content.decode(chardet_result['encoding'] or 'utf-8', 'ignore')
        except UnicodeDecodeError as e:
            data = content.decode('utf-8', 'ignore')

        flag = False
        send_result = Settings._send_telegram_message(data)
        if len(send_result) > 0:
            flag = True
        send_result = Settings._send_dingding_message(data)
        if send_result is True:
            flag = True
        send_result = Settings._send_serverchan_message(data)
        if send_result is True:
            flag = True
        return flag
