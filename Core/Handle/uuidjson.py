# -*- coding: utf-8 -*-
# @File  : uuidjson.py
# @Date  : 2021/12/16
# @Desc  :
import datetime
import json

from Lib.api import data_return
from Lib.configs import UUID_JSON_MSG_ZH, UUID_JSON_MSG_EN
from Lib.log import logger
from Lib.notice import Notice
from Lib.xcache import Xcache


class UUIDJson(object):
    def __init__(self):
        pass

    @staticmethod
    def list(uuid):
        data = Xcache.get_uuid_json_by_uuid(uuid)
        return data

    @staticmethod
    def store_data_from_sub(message=None):
        """处理msf发送的notice信息print_XXX_redis"""
        body = message.get('data')
        try:
            uuid_json_dict = json.loads(body)
            uuid = uuid_json_dict.get("UUID")
            tag = uuid_json_dict.get("TAG")
            level = uuid_json_dict.get("LEVEL")
            # data = uuid_json_dict.get("DATA")
            uuid_json_dict["UPDATETIME"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if level in ["WARNING", "ERROR"]:
                Notice.send_warning(f"RPCMSG: TAG:{tag} - LEVEL:{level} - UUID:{uuid}",
                                    f"RPCMSG: TAG:{tag} - LEVEL:{level} - UUID:{uuid}")
            Xcache.set_uuid_json_by_uuid(uuid, uuid_json_dict)
        except Exception as E:
            logger.error(E)
            return False

    @staticmethod
    def store_uuid_json(uuid_json_dict):
        try:
            uuid = uuid_json_dict.get("UUID")
            tag = uuid_json_dict.get("TAG")
            level = uuid_json_dict.get("LEVEL")
            # data = uuid_json_dict.get("DATA")
            uuid_json_dict["UPDATETIME"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if level in ["WARNING", "ERROR"]:
                Notice.send_warning(f"RPCMSG: TAG:{tag} - LEVEL:{level} - UUID:{uuid}",
                                    f"RPCMSG: TAG:{tag} - LEVEL:{level} - UUID:{uuid}")
            Xcache.set_uuid_json_by_uuid(uuid, uuid_json_dict)
        except Exception as E:
            logger.error(E)
            return False

    @staticmethod
    def destory():
        Xcache.del_uuid_json()
        context = data_return(202, {}, UUID_JSON_MSG_ZH.get(202), UUID_JSON_MSG_EN.get(202))
        return context
