# -*- coding: utf-8 -*-
# @File  : baseauth.py
# @Date  : 2021/2/25
# @Desc  :
import datetime

from django.core.cache import cache
from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication

from Lib.configs import EXPIRE_MINUTES


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
