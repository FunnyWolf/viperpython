# -*- coding: utf-8 -*-
# @File  : fofaclient.py
# @Date  : 2021/2/25
# @Desc  :

import urllib3
from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

from Lib.api import random_str
from Lib.xcache import Xcache

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OpenAISetting(object):
    def __init__(self):
        pass

    @staticmethod
    def list():
        openai_conf = Xcache.list_openai_conf()
        result = []
        for conf_id in openai_conf:
            openai_conf[conf_id]["id"] = conf_id
            result.append(openai_conf[conf_id])
        return result

    @staticmethod
    def add(conf):
        conf["id"] = random_str(16)
        conf_dict = Xcache.list_openai_conf()
        conf_dict[conf["id"]] = conf
        Xcache.set_openai_conf(conf_dict)
        return conf_dict

    @staticmethod
    def delete(key):
        conf_dict = Xcache.list_openai_conf()
        if conf_dict.get(key) is None:
            return False
        conf_dict.pop(key)
        Xcache.set_openai_conf(conf_dict)
        return True


class OpenAIAPI(object):
    def __init__(self):
        self.api_key = None
        self.base_url = None  # https://api.openai.com  https://api.bianxieai.com
        self.model = None
        self.temperature = 1
        self.alive = False

    def set_api_key(self, api_key):
        self.api_key = api_key

    def set_base_url(self, base_url: str):
        self.base_url = base_url.rstrip('/')

    def set_temperature(self, temperature: float):
        self.temperature = temperature

    def set_model(self, model: str):
        self.model = model

    # def init(self):
    #     self.set_api_key(conf.get("api_key"))
    #     self.set_base_url(conf.get("base_url"))
    #     self.set_model(conf.get("model"))
    #     self.alive = conf.get("alive")

    def store_conf(self):
        conf = {"api_key": self.api_key, "base_url": self.base_url, "model": self.model, "alive": True}
        OpenAISetting.add(conf)

    def get_model(self, easy=None, reasoning=None, function_calling=None):
        conf_list = OpenAISetting.list()
        for conf in conf_list:
            if easy is not None:
                if easy != conf.get("easy"):
                    continue
            if reasoning is not None:
                if reasoning != conf.get("reasoning"):
                    continue
            if function_calling is not None:
                if function_calling != conf.get("function_calling"):
                    continue

            self.set_api_key(conf.get("api_key"))
            self.set_base_url(conf.get("base_url"))
            self.set_model(conf.get("model"))

            return ChatOpenAI(
                base_url=self.base_url,
                api_key=self.api_key,
                model=self.model,
                temperature=self.temperature,
            )
        raise Exception("No OpenAI model meet the requirement")

    def is_alive(self):
        model = ChatOpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            model=self.model,
            temperature=self.temperature,
        )
        parser = StrOutputParser()
        chain = model | parser
        messages = [
            ("system", "give you `ping` reply `pong`."),
            ("human", "ping"),
        ]
        try:
            ai_msg = chain.invoke(messages)
            self.alive = True
            return True
        except Exception as e:
            self.alive = False
            return False

    @staticmethod
    def is_model_alive(model: ChatOpenAI):
        parser = StrOutputParser()
        chain = model | parser
        messages = [
            ("system", "give you `ping` reply `pong`."),
            ("human", "ping"),
        ]
        try:
            ai_msg = chain.invoke(messages)
            return True
        except Exception as e:
            return False
