# -*- coding: utf-8 -*-
# @File  : api.py
# @Date  : 2021/2/25
# @Desc  :
import json
import random
import string
import uuid


def random_str(len):
    value = ''.join(random.sample(string.ascii_letters + string.digits, len))
    return value


def random_int(num):
    """生成随机字符串"""
    return random.randint(1, num)


def is_json(data):
    try:
        json.loads(data)
        return True
    except Exception as E:
        return False


def get_one_uuid_str():
    uuid_str = str(uuid.uuid1()).replace('-', "")[0:16]
    return uuid_str


def data_return(code=500, data=None,
                msg_zh="服务器发生错误，请检查服务器",
                msg_en="An error occurred on the server, please check the server."):
    return {'code': code, 'data': data, 'msg_zh': msg_zh, "msg_en": msg_en}


class UnicodeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode(encoding='utf-8', errors="ignore").encode(encoding='utf-8', errors="ignore")
        elif isinstance(obj, str):
            return obj.encode(encoding='utf-8', errors="ignore").decode(encoding='utf-8', errors="ignore")
        return json.JSONEncoder.default(self, obj)


class UnicodeDecoder(json.JSONDecoder):
    def decode(self, s):
        s = s.encode(encoding='utf-8', errors="ignore").decode(encoding='utf-8', errors="ignore")
        return super().decode(s)


def u_json_dumps(data):
    return json.dumps(data, cls=UnicodeEncoder)


def u_json_loads(data):
    return json.loads(data, cls=UnicodeDecoder)
