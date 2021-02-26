# -*- coding: utf-8 -*-
# @File  : redisclient.py
# @Date  : 2021/2/25
# @Desc  :
import redis

from CONFIG import REDIS_URL
from Lib.log import logger


class RedisClient(object):

    def __init__(self):
        pass

    @staticmethod
    def get_result_connection():
        try:
            rcon = redis.Redis.from_url(url=f"{REDIS_URL}5")
            return rcon
        except Exception as E:
            logger.warning(E)
            return None
