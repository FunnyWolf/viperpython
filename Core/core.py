# -*- coding: utf-8 -*-
# @File  : core.py
# @Date  : 2019/1/11
# @Desc  :

import base64
import datetime
import json
import ssl
from urllib.parse import urlencode
from urllib.request import urlopen, Request

import requests
import telegram
from django.db import transaction
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication
from telegram.bot import Bot

from Core.configs import *
from Core.lib import *
from Core.serializers import *
from Msgrpc.msgrpc import FileMsf
from Msgrpc.msgrpc import Session
from PostLateral.models import PortServiceModel, VulnerabilityModel
from PostLateral.postlateral import PortService

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class BaseAuth(TokenAuthentication):
    def authenticate_credentials(self, key=None):
        # 搜索缓存的user
        cache_user = cache.get(key)
        if cache_user:
            return cache_user, key

        model = self.get_model()
        try:
            token = model.objects.select_related('user').get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed()

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed()

        # token超时
        time_now = datetime.datetime.now()
        if token.created < time_now - datetime.timedelta(minutes=EXPIRE_MINUTES):
            token.delete()
            raise exceptions.AuthenticationFailed()

        if token:
            # 缓存token
            cache.set(key, token.user, EXPIRE_MINUTES * 60)

        return token.user, token


class CurrentUser(object):
    def __init__(self):
        pass

    @staticmethod
    def list(user=None):
        current_info = {
            'name': user.username,
            'avatar': 'user',
            'userid': user.id,
        }

        return current_info


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
        elif kind == "FOFA":
            conf = Xcache.get_fofa_conf()
            if conf is None:
                conf = {"email": "", "key": "", "alive": False}
        elif kind == "sessionmonitor":
            conf = Xcache.get_sessionmonitor_conf()
        else:
            context = dict_data_return(301, Setting_MSG.get(301), {})
            return context

        context = dict_data_return(200, CODE_MSG.get(200), conf)
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
                user_chat_id_list = Settings._get_alive_chat_id(token, proxy)

                context = dict_data_return(201, Setting_MSG.get(201), user_chat_id_list)
                return context
            else:
                if Settings._check_telegram_aliveable(token, chat_id, proxy) is not True:
                    data = {"token": token, "chat_id": chat_id, "proxy": proxy, "alive": False}
                    Xcache.set_telegram_conf(data)
                    context = dict_data_return(303, Setting_MSG.get(303), data)
                    return context
                else:
                    Notices.send_success("设置Telegram通知成功")
                    data = {"token": token, "chat_id": chat_id, "proxy": proxy, "alive": True}
                    Xcache.set_telegram_conf(data)
                    context = dict_data_return(202, Setting_MSG.get(202), data)
                    return context

        elif kind == "dingding":
            access_token = setting.get("access_token")
            keyword = setting.get("keyword")

            if Settings._check_dingding_aliveable(access_token, keyword) is not True:
                data = {"access_token": access_token, "keyword": keyword, "alive": False}
                Xcache.set_dingding_conf(data)
                context = dict_data_return(304, Setting_MSG.get(304), data)
                return context
            else:
                Notices.send_success("设置DingDing通知成功")
                data = {"access_token": access_token, "keyword": keyword, "alive": True}
                Xcache.set_dingding_conf(data)

                context = dict_data_return(203, Setting_MSG.get(203), data)
                return context

        elif kind == "FOFA":
            email = setting.get("email")
            key = setting.get("key")
            client = FOFAClient()
            client.set_email_and_key(email, key)
            if client.is_alive() is not True:
                data = {"email": email, "key": key, "alive": False}
                Xcache.set_fofa_conf(data)
                context = dict_data_return(306, Setting_MSG.get(306), data)
                return context
            else:
                Notices.send_success("设置FOFA API 成功")
                data = {"email": email, "key": key, "alive": True}
                Xcache.set_fofa_conf(data)
                context = dict_data_return(206, Setting_MSG.get(206), data)
                return context

        elif kind == "sessionmonitor":
            flag = setting.get("flag")
            Xcache.set_sessionmonitor_conf({"flag": flag})
            Notices.send_success(f"设置Session监控成功,当前状态: {flag}")

            context = dict_data_return(204, Setting_MSG.get(204), {"flag": flag})
            return context

        elif kind == "lhost":
            Xcache.set_lhost_config(setting)
            Notices.send_success(f"设置回连地址成功,当前回连地址: {setting.get('lhost')}")
            context = dict_data_return(205, Setting_MSG.get(205), setting)
            return context
        else:
            context = dict_data_return(301, Setting_MSG.get(301), {})
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
    def _get_alive_chat_id(token=None, proxy=None):
        if proxy is None or proxy == "":
            bot = Bot(token=token)
        else:
            proxy_url = proxy
            request = telegram.utils.request.Request(proxy_url=proxy_url)
            bot = Bot(token=token, request=request)
        user_chat_id_list = []
        try:
            result = bot.get_updates()
        except Exception as E:
            logger.exception(E)
            return user_chat_id_list
        for update in result:
            first_name = update.effective_chat.first_name if update.effective_chat.first_name is not None else ""
            last_name = update.effective_chat.last_name if update.effective_chat.last_name is not None else ""
            one_data = {
                "user": "{}{}".format(first_name, last_name),
                "chat_id": update.effective_chat.id
            }
            if one_data not in user_chat_id_list:
                user_chat_id_list.append(one_data)
        return user_chat_id_list

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

        token = conf.get("token")
        chat_id = conf.get("chat_id")
        proxy = conf.get("proxy")
        if isinstance(chat_id, str):
            chat_id = [chat_id]
        elif isinstance(chat_id, list):
            pass
        else:
            return []
        send_result = []
        if proxy is None or proxy == "":
            try:
                bot = Bot(token=token)
            except Exception as E:
                logger.exception(E)
                return []
        else:
            # proxy_url = 'socks5://127.0.0.1:1080'
            proxy_url = proxy
            request = telegram.utils.request.Request(proxy_url=proxy_url)
            try:
                bot = Bot(token=token, request=request)
            except Exception as E:
                logger.exception(E)
                return []
        for one_chat_id in chat_id:
            try:
                bot.send_message(chat_id=one_chat_id, text=msg, timeout=1)
                send_result.append(one_chat_id)
            except Exception as E:
                logger.exception(E)
                logger.warning("无效的chat_id: {}".format(one_chat_id))
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
            return []
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


class HostAndSession(object):
    def __init__(self):
        pass

    @staticmethod
    def list_hostandsession():
        hosts = Host.list_hosts()
        sessions = Session.list_sessions()

        # 初始化session列表
        for host in hosts:
            host['session'] = None

        hosts_with_session = []

        # 聚合Session和host
        host_exist = False
        for session in sessions:
            for host in hosts:
                if session.get("session_host") == host.get('ipaddress'):
                    temp_host = copy.deepcopy(host)
                    temp_host['session'] = session
                    hosts_with_session.append(temp_host)
                    host_exist = True
                    break

            if host_exist is True:
                host_exist = False
            else:
                if session.get("session_host") is None or session.get("session_host") == "":
                    host_exist = False
                else:
                    # 减少新建无效的host
                    if session.get("available"):
                        host_create = Host.create_host(session.get("session_host"))
                    else:
                        host_create = Host.create_host("255.255.255.255")
                    host_create['session'] = session
                    hosts_with_session.append(host_create)
                    host_exist = False

        for host in hosts:
            add = True
            for temp_host in hosts_with_session:
                if temp_host.get("id") == host.get("id"):
                    add = False
                    break
            if add:
                hosts_with_session.append(host)

        # 设置host的proxy信息
        # 收集所有hostip
        ipaddress_list = []
        for host in hosts_with_session:
            ipaddress_list.append(host.get('ipaddress'))

        i = 0
        for one in hosts_with_session:
            one["order_id"] = i
            i += 1

        return hosts_with_session


class Host(object):
    REGISTER_DESTORY = [PortServiceModel, VulnerabilityModel]  # 删除Host时同时删除列表中的数据

    def __init__(self):
        pass

    @staticmethod
    def list():
        hosts = Host.list_hosts()
        for host in hosts:
            hid = host.get('id')
            host['portService'] = PortService.list_by_hid(hid)

        context = list_data_return(200, CODE_MSG.get(200), hosts)
        return context

    @staticmethod
    def get_by_ipaddress(ipaddress=None):
        try:
            model = HostModel.objects.get(ipaddress=ipaddress)
            result = HostSerializer(model).data
            return result
        except Exception as E:
            result = Host.create_host(ipaddress)
            logger.info(E)
            return result

    @staticmethod
    def get_by_hid(hid=None):
        try:
            model = HostModel.objects.get(id=hid)
            result = HostSerializer(model).data
            return result
        except Exception as E:
            logger.warning(E)
            return None

    @staticmethod
    def list_hosts():
        models = HostModel.objects.all()
        result = HostSerializer(models, many=True).data
        return result

    @staticmethod
    def create_host(ipaddress=None):
        defaultdict = {'ipaddress': ipaddress, }  # 没有主机数据时新建
        model, created = HostModel.objects.get_or_create(ipaddress=ipaddress, defaults=defaultdict)
        if created is True:
            result = HostSerializer(model, many=False).data
            return result  # 新建后直接返回
        # 有历史数据
        with transaction.atomic():
            try:
                model = HostModel.objects.select_for_update().get(id=model.id)
                model.ipaddress = ipaddress

                model.save()
                result = HostSerializer(model, many=False).data
                return result
            except Exception as E:
                logger.error(E)
                result = HostSerializer(model, many=False).data
                return result

    @staticmethod
    def update(hid=None, tag=None, comment=None):
        """更新主机标签,说明"""
        host_update = Host.update_host(hid, tag, comment)
        if host_update is None:
            context = dict_data_return(304, Host_MSG.get(304), host_update)
        else:
            context = dict_data_return(201, Host_MSG.get(201), host_update)
        return context

    @staticmethod
    def update_host(id=None, tag=None, comment=None):

        defaultdict = {'id': id, 'tag': tag, 'comment': comment}  # 没有此主机数据时新建
        model, created = HostModel.objects.get_or_create(id=id, defaults=defaultdict)
        if created is True:
            result = HostSerializer(model, many=False).data
            return result  # 新建后直接返回
        # 有历史数据
        with transaction.atomic():
            try:
                model = HostModel.objects.select_for_update().get(id=id)
                model.tag = tag
                model.comment = comment
                model.save()
                result = HostSerializer(model, many=False).data
                return result
            except Exception as E:
                logger.error(E)
                return None

    @staticmethod
    def destory_single(hid=-1):
        hid_flag = Host.destory_host(hid)
        if hid_flag:
            context = dict_data_return(202, Host_MSG.get(202), {})
        else:
            context = dict_data_return(301, Host_MSG.get(301), {})
        return context

    @staticmethod
    def destory_mulit(hids):
        for hid in hids:
            Host.destory_host(hid)

        context = dict_data_return(202, Host_MSG.get(202), {})
        return context

    @staticmethod
    def destory_host(id=None):
        # 删除相关缓存信息
        host = Host.get_by_hid(hid=id)
        # 删除缓存的session命令行结果
        Xcache.del_sessionio_cache(hid=id)
        # 删除缓存的模块结果
        Xcache.del_module_result_by_hid(ipaddress=host.get("ipaddress"))
        # 删除缓存的模块历史结果
        Xcache.del_module_result_history_by_hid(ipaddress=host.get("ipaddress"))

        try:
            # 删除主表信息
            HostModel.objects.filter(id=id).delete()
            # 删除关联表信息
            for OneModel in Host.REGISTER_DESTORY:
                OneModel.objects.filter(hid=id).delete()
            return True
        except Exception as E:
            logger.error(E)
            return False


class FOFAClient:
    def __init__(self):
        self.email = None
        self.key = None
        self.base_url = "https://fofa.so"
        self.search_api_url = "/api/v1/search/all"
        self.login_api_url = "/api/v1/info/my"
        self.fields = ["ip", "port", "protocol", "country_name", "as_organization"]

    def set_email_and_key(self, email, key):
        self.email = email
        self.key = key

    def init_conf_from_cache(self):
        conf = Xcache.get_fofa_conf()
        if conf is None:
            return False
        else:
            if conf.get("alive") is not True:
                return False
            else:
                self.email = conf.get("email")
                self.key = conf.get("key")
                return True

    def get_userinfo(self):
        api_full_url = "%s%s" % (self.base_url, self.login_api_url)
        param = {"email": self.email, "key": self.key}
        res = self.__http_get(api_full_url, param)
        return json.loads(res)

    def is_alive(self):
        # {"email":"XXX@XXX.org","username":"XXX","fcoin":0,"isvip":true,"vip_level":2,"is_verified":false,"avatar":"https://nosec.org/missing.jpg","message":0,"fofacli_ver":"3.10.4","fofa_server":true}
        userdata = self.get_userinfo()
        if userdata.get("email") == self.email:
            return True
        else:
            return False

    def get_data(self, query_str, page=1, size=100):
        res = self.get_json_data(query_str, page, size)
        data = json.loads(res)
        format_results = []
        if data.get("error") is False:
            results = data.get("results")
            for result in results:
                format_result = {}
                for field, value in zip(self.fields, result):
                    format_result[field] = value
                format_results.append(format_result)
            return True, format_results
        else:
            return False, data.get("errmsg")

    def get_json_data(self, query_str, page=1, size=100):
        api_full_url = "%s%s" % (self.base_url, self.search_api_url)
        param = {"qbase64": base64.b64encode(query_str.encode(encoding="UTF-8", errors="ignore")), "email": self.email,
                 "key": self.key,
                 "page": page,
                 "size": size,
                 "fields": ",".join(self.fields)}
        res = self.__http_get(api_full_url, param)
        return res

    @staticmethod
    def __http_get(url, param):
        param = urlencode(param)
        url = "%s?%s" % (url, param)

        try:
            r = requests.get(url=url, verify=False, headers={'Connection': 'close'})
            return r.text
        except Exception as e:
            raise e


class NetworkSearch(object):
    """网络搜索引擎"""

    def __init__(self):
        pass

    @staticmethod
    def list(engine, querystr, page=1, size=100):
        if engine == "FOFA":
            client = FOFAClient()
            flag = client.init_conf_from_cache()
            if flag is not True:
                context = dict_data_return(301, NetworkSearch_MSG.get(301), {})
                return context

        else:
            context = dict_data_return(304, NetworkSearch_MSG.get(304), {})
            return context

        try:
            flag, data = client.get_data(query_str=querystr, page=page, size=size)
            if flag is not True:
                context = dict_data_return(303, NetworkSearch_MSG.get(303), {"errmsg": data})
            else:
                context = list_data_return(200, CODE_MSG.get(200), data)
            return context

        except Exception as E:
            logger.exception(E)
            context = dict_data_return(303, NetworkSearch_MSG.get(303), {"errmsg": NetworkSearch_MSG.get(303)})
            return context


class NetworkTopology(object):
    """网络图,废弃"""

    def __init__(self):
        pass

    @staticmethod
    def load_cache():
        cache_data = Xcache.get_network_topology_cache()
        if cache_data is None:
            cache_data = {}
        context = dict_data_return(200, CODE_MSG.get(200), cache_data)
        return context

    @staticmethod
    def set_cache(cache_data):
        Xcache.set_network_topology_cache(cache_data)
        context = dict_data_return(201, CODE_MSG.get(201), {})
        return context


class DingDing(object):
    SHOW_AVATAR = "0"  # 不隐藏头像
    HIDE_AVATAR = "1"  # 隐藏头像

    BTN_CROSSWISE = "0"  # 横向
    BTN_LENGTHWAYS = "1"  # 纵向

    def __init__(self, token=None):
        self.url = self.parse_token(token)
        self.headers = {"Content-Type": "application/json"}

    @staticmethod
    def parse_token(token=None):
        """
        :param token:
        :return:
        """
        ding_url_pre = "https://oapi.dingtalk.com/robot/send?access_token=%s"
        token = token.strip()
        if len(token) == 64:
            return ding_url_pre % token

        if len(token) == 114:
            return token

        raise ValueError("token Error")

    def send_text(self, text=None, at_mobiles=None, at_all=False, keyword=''):
        """
        例子: send_text('天气不错', ['13333333333'])
        :param text: 消息类型，此时固定为:text
        :param at_mobiles: 被@人的手机号 ['13333333333', ]
        :param at_all: @所有人时:true,否则为:false
        :param keyword: 关键字
        :return:
        """
        if at_mobiles is None:
            at_mobiles = []
        data = {
            "msgtype": "text",
            "text": {"content": f"<{keyword}>\n{text}"},
            "at": {"atMobiles": at_mobiles, "isAtAll": at_all},
        }
        return self._post(data)

    def send_link(self, title=None, text=None, message_url="", pic_url=""):
        data = {
            "msgtype": "link",
            "link": {
                "text": text,
                "title": title,
                "picUrl": pic_url,
                "messageUrl": message_url,
            },
        }
        return self._post(data)

    def send_markdown(self, title=None, text=None, at_mobiles=None, at_all=False):
        """发送markdown格式

        :param title: 首屏会话透出的展示内容
        :param text: markdown格式的消息
        :param at_mobiles: 被@人的手机号(在text内容里要有@手机号)
        :param at_all: @所有人时:true,否则为:false
        :return:
        """
        if at_mobiles is None:
            at_mobiles = []
        data = {
            "msgtype": "markdown",
            "markdown": {"title": title, "text": text},
            "at": {"atMobiles": at_mobiles, "isAtAll": at_all},
        }
        return self._post(data)

    def send_single_action_card(
            self,
            title=None,
            text=None,
            single_title=None,
            single_url=None,
            btn_orientation=BTN_LENGTHWAYS,
            hide_avatar=SHOW_AVATAR,
    ):
        """整体跳转ActionCard类型

        :param title: 首屏会话透出的展示内容
        :param text: markdown格式的消息
        :param single_title: 单个按钮的方案。(设置此项和singleURL后btns无效。)
        :param single_url: 点击singleTitle按钮触发的URL
        :param btn_orientation: 0-按钮竖直排列，1-按钮横向排列
        :param hide_avatar: 0-正常发消息者头像,1-隐藏发消息者头像
        :return:
        """
        data = {
            "actionCard": {
                "title": title,
                "text": text,
                "hideAvatar": hide_avatar,
                "btnOrientation": btn_orientation,
                "singleTitle": single_title,
                "singleURL": single_url,
            },
            "msgtype": "actionCard",
        }
        return self._post(data)

    def send_action_card(
            self, title=None, text=None, btns=None, btn_orientation=BTN_LENGTHWAYS, hide_avatar=SHOW_AVATAR
    ):
        """独立跳转ActionCard类型

        :param title: 首屏会话透出的展示内容
        :param text: markdown格式的消息
        :param btns: 按钮的信息：title-按钮方案，actionURL-点击按钮触发的URL
        :param btn_orientation: 0-按钮竖直排列，1-按钮横向排列
        :param hide_avatar: 0-正常发消息者头像,1-隐藏发消息者头像
        :return:
        """
        btns = [{"title": btn[0], "actionURL": btn[1]} for btn in btns]
        data = {
            "actionCard": {
                "title": title,
                "text": text,
                "hideAvatar": hide_avatar,
                "btnOrientation": btn_orientation,
                "btns": btns,
            },
            "msgtype": "actionCard",
        }
        return self._post(data)

    def send_feed_card(self, rows=None):
        """FeedCard类型
        例子: send_feed_card([('学vue','https://cn.vuejs.org/','https://cn.vuejs.org/images/logo.png'),
                     ('哪家强', 'https://cn.vuejs.org/', 'https://cn.vuejs.org/images/logo.png')])
        :param rows: [(title, messageURL, picURL), (...)]
        :return:
        """
        rows = [
            {"title": row[0], "messageURL": row[1], "picURL": row[2]} for row in rows
        ]
        data = {"feedCard": {"links": rows}, "msgtype": "feedCard"}
        return self._post(data)

    def _post(self, data=None):
        data = json.dumps(data)
        req = Request(self.url, data=data.encode("utf-8"), headers=self.headers)
        context = ssl._create_unverified_context()
        response = urlopen(req, context=context)
        the_page = response.read()
        return json.loads(the_page.decode("utf-8"))
