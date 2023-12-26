# -*- coding: utf-8 -*-
# @File  : telegram.py
# @Date  : 2021/2/26
# @Desc  :
import telegram
from telegram import Bot

from Lib.log import logger


class Telegram(object):
    @staticmethod
    def send_text(token, chat_id, proxy, msg):
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
                logger.warning(f"无效的chat_id: {one_chat_id}")
        return send_result

    @staticmethod
    def get_alive_chat_id(token=None, proxy=None):
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
                "user": f"{first_name}{last_name}",
                "chat_id": update.effective_chat.id
            }
            if one_data not in user_chat_id_list:
                user_chat_id_list.append(one_data)
        return user_chat_id_list
