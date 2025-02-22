# -*- coding: utf-8 -*-
# @File  : aescrypt.py
# @Date  : 2021/2/26
# @Desc  :
import base64

from Crypto.Cipher import AES


class Aescrypt(object):
    def __init__(self, key, model, iv, encode_):
        self.encode_ = encode_
        self.model = {'ECB': AES.MODE_ECB, 'CBC': AES.MODE_CBC}[model]
        self.key = self.add_16(key)
        if model == 'ECB':
            self.aes = AES.new(self.key, self.model)  # 创建一个aes对象
        elif model == 'CBC':
            self.aes = AES.new(self.key, self.model, iv)  # 创建一个aes对象

    def add_16(self, par):
        par = par.encode(self.encode_)
        while len(par) % 16 != 0:
            par += b'\0'
        return par

    def aesencrypt(self, text):
        text = self.add_16(text)
        encrypt_text = self.aes.encrypt(text)
        return base64.encodebytes(encrypt_text).decode().strip()

    def aesdecrypt(self, text):
        text = base64.decodebytes(text.encode(self.encode_))
        decrypt_text = self.aes.decrypt(text)
        return decrypt_text.decode(self.encode_).strip('\0')
