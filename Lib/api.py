# -*- coding: utf-8 -*-
# @File  : api.py
# @Date  : 2021/2/25
# @Desc  :
import socket

from Lib.log import logger


def is_empty_ports(useport=None):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("0.0.0.0", useport))
        sock.close()
        return True, ""
    except socket.error:
        logger.warning(f"端口: {useport},已占用")
        return False, ""


def data_return(code, message, data):
    return {'code': code, 'message': message, 'data': data}
