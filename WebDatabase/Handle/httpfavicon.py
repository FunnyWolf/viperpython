# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from WebDatabase.documents import HttpFaviconDocument


class HttpFavicon(object):

    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        doc = HttpFaviconDocument(ipdomain=ipdomain, port=port)
        return doc.get_dict()
