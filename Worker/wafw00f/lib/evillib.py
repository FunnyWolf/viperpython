#!/usr/bin/env python
'''
Copyright (C) 2022, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

import time
from copy import copy

import requests
import urllib3
from lib.log import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def_headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.9',
    'DNT': '1',  # Do Not Track request header
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3770.100 Safari/537.36',
    'Upgrade-Insecure-Requests': '1'  #
}
proxies = {}


class waftoolsengine:
    def __init__(self, target='https://example.com', path='/', proxies=None,
                 redir=True, head=None):
        self.target = target
        self.requestnumber = 0
        self.path = path
        self.redirectno = 0
        self.allowredir = redir
        self.proxies = proxies
        self.timeout = 1
        if head:
            self.headers = head
        else:
            self.headers = copy(def_headers)  # copy object by value not reference. Fix issue #90
        self.session = requests.session()

    def Request(self, headers=None, path=None, params={}, delay=0):
        try:
            time.sleep(delay)
            if not headers:
                h = self.headers
            else:
                h = headers

            req = self.session.get(self.target, proxies=self.proxies, headers=h, timeout=self.timeout,
                                   allow_redirects=self.allowredir, params=params, verify=False)

            self.requestnumber += 1
            return req
        except requests.exceptions.RequestException as e:
            logger.debug(e)
            return None
