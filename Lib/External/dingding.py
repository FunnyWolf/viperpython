# -*- coding: utf-8 -*-
# @File  : dingding.py
# @Date  : 2021/2/25
# @Desc  :
import json
import ssl
from urllib.request import Request, urlopen


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
