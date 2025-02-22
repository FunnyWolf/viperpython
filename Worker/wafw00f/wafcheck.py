#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Copyright (C) 2022, WAFW00F Developers.
See the LICENSE file for copying permission.
'''
# For keeping python2 support for now

import random
import re
import string
import time

import gevent
from gevent.pool import Pool
from lib.log import logger
from wafw00f.lib.evillib import waftoolsengine
from wafw00f.manager import load_plugins
from wafw00f.wafprio import wafdetectionsprio


class WAFW00F(waftoolsengine):
    xsstring = '<script>alert("XSS");</script>'
    sqlistring = "UNION SELECT ALL FROM information_schema AND ' or SLEEP(5) or '"
    lfistring = '../../../../etc/passwd'
    rcestring = '/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com'
    xxestring = '<!ENTITY xxe SYSTEM "file:///etc/shadow">]><pwn>&hack;</pwn>'

    def __init__(self, target='www.example.com', path='/',
                 followredirect=True, extraheaders={}, proxies=None, timeout=1):

        self.attackres = None
        waftoolsengine.__init__(self, target, path, proxies, followredirect, extraheaders)
        self.knowledge = dict(generic=dict(found=False, reason=''), wafname=list())
        self.timeout = timeout
        self.rq = self.normalRequest()

        self.wafdetections = dict()

        plugin_dict = load_plugins()
        result_dict = {}
        for plugin_module in plugin_dict.values():
            self.wafdetections[plugin_module.NAME] = plugin_module.is_waf
        self.checklist = wafdetectionsprio
        self.checklist += list(set(self.wafdetections.keys()) - set(self.checklist))

    def normalRequest(self):
        return self.Request()

    def customRequest(self, headers=None):
        return self.Request(
            headers=headers
        )

    def nonExistent(self):
        return self.Request(
            path=self.path + str(random.randrange(100, 999)) + '.html'
        )

    def xssAttack(self):
        return self.Request(
            path=self.path,
            params={
                create_random_param_name(): self.xsstring
            }
        )

    def xxeAttack(self):
        return self.Request(
            path=self.path,
            params={
                create_random_param_name(): self.xxestring
            }
        )

    def lfiAttack(self):
        return self.Request(
            path=self.path + self.lfistring
        )

    def centralAttack(self):
        return self.Request(
            path=self.path,
            params={
                create_random_param_name(): self.xsstring,
                create_random_param_name(): self.sqlistring,
                create_random_param_name(): self.lfistring
            }
        )

    def sqliAttack(self):
        return self.Request(
            path=self.path,
            params={
                create_random_param_name(): self.sqlistring
            }
        )

    def osciAttack(self):
        return self.Request(
            path=self.path,
            params={
                create_random_param_name(): self.rcestring
            }
        )

    def performCheck(self, request_method):
        r = request_method()
        if r is None:
            raise RequestBlocked()
        return r, r.url

    # Most common attacks used to detect WAFs
    attcom = [xssAttack, sqliAttack, lfiAttack]
    attacks = [xssAttack, xxeAttack, lfiAttack, sqliAttack, osciAttack]

    def genericdetect(self):
        reason = ''
        reasons = ['Blocking is being done at connection/packet level.',
                   'The server header is different when an attack is detected.',
                   'The server returns a different response code when an attack string is used.',
                   'It closed the connection for a normal request.',
                   'The response was different when the request wasn\'t made from a browser.'
                   ]
        try:
            # Testing for no user-agent response. Detects almost all WAFs out there.
            resp1, _ = self.performCheck(self.normalRequest)
            if 'User-Agent' in self.headers:
                self.headers.pop('User-Agent')  # Deleting the user-agent key from object not dict.
            resp3 = self.customRequest(headers=self.headers)
            if resp3 is not None and resp1 is not None:
                if resp1.status_code != resp3.status_code:
                    logger.debug(
                        'Server returned a different response when request didn\'t contain the User-Agent header.')
                    reason = reasons[4]
                    reason += '\r\n'
                    reason += 'Normal response code is "%s",' % resp1.status_code
                    reason += ' while the response code to a modified request is "%s"' % resp3.status_code
                    self.knowledge['generic']['reason'] = reason
                    self.knowledge['generic']['found'] = True
                    return True

            # Testing the status code upon sending a xss attack
            resp2, xss_url = self.performCheck(self.xssAttack)
            if resp1.status_code != resp2.status_code:
                logger.debug('Server returned a different response when a XSS attack vector was tried.')
                reason = reasons[2]
                reason += '\r\n'
                reason += 'Normal response code is "%s",' % resp1.status_code
                reason += ' while the response code to cross-site scripting attack is "%s"' % resp2.status_code
                self.knowledge['generic']['reason'] = reason
                self.knowledge['generic']['found'] = True
                return xss_url

            # Testing the status code upon sending a lfi attack
            resp2, lfi_url = self.performCheck(self.lfiAttack)
            if resp1.status_code != resp2.status_code:
                logger.debug('Server returned a different response when a directory traversal was attempted.')
                reason = reasons[2]
                reason += '\r\n'
                reason += 'Normal response code is "%s",' % resp1.status_code
                reason += ' while the response code to a file inclusion attack is "%s"' % resp2.status_code
                self.knowledge['generic']['reason'] = reason
                self.knowledge['generic']['found'] = True
                return lfi_url

            # Testing the status code upon sending a sqli attack
            resp2, sqli_url = self.performCheck(self.sqliAttack)
            if resp1.status_code != resp2.status_code:
                logger.debug('Server returned a different response when a SQLi was attempted.')
                reason = reasons[2]
                reason += '\r\n'
                reason += 'Normal response code is "%s",' % resp1.status_code
                reason += ' while the response code to a SQL injection attack is "%s"' % resp2.status_code
                self.knowledge['generic']['reason'] = reason
                self.knowledge['generic']['found'] = True
                return sqli_url

            # Checking for the Server header after sending malicious requests
            normalserver, attackresponse_server = '', ''
            response = self.attackres
            if 'server' in resp1.headers:
                normalserver = resp1.headers.get('Server')
            if response is not None and 'server' in response.headers:
                attackresponse_server = response.headers.get('Server')
            if attackresponse_server != normalserver:
                logger.debug('Server header changed, WAF possibly detected')
                logger.debug('Attack response: %s' % attackresponse_server)
                logger.debug('Normal response: %s' % normalserver)
                reason = reasons[1]
                reason += '\r\nThe server header for a normal response is "%s",' % normalserver
                reason += ' while the server header a response to an attack is "%s",' % attackresponse_server
                self.knowledge['generic']['reason'] = reason
                self.knowledge['generic']['found'] = True
                return True

        # If at all request doesn't go, press F
        except RequestBlocked:
            self.knowledge['generic']['reason'] = reasons[0]
            self.knowledge['generic']['found'] = True
            return True
        return False

    def matchHeader(self, headermatch, attack=False):
        if attack:
            r = self.attackres
        else:
            r = self.rq
        if r is None:
            return

        header, match = headermatch
        headerval = r.headers.get(header)
        if headerval:
            # set-cookie can have multiple headers, python gives it to us
            # concatinated with a comma
            if header == 'Set-Cookie':
                headervals = headerval.split(', ')
            else:
                headervals = [headerval]
            for headerval in headervals:
                if re.search(match, headerval, re.I):
                    return True
        return False

    def matchStatus(self, statuscode, attack=True):
        if attack:
            r = self.attackres
        else:
            r = self.rq
        if r is None:
            return
        if r.status_code == statuscode:
            return True
        return False

    def matchCookie(self, match, attack=False):
        return self.matchHeader(('Set-Cookie', match), attack=attack)

    def matchReason(self, reasoncode, attack=True):
        if attack:
            r = self.attackres
        else:
            r = self.rq
        if r is None:
            return
        # We may need to match multiline context in response body
        if str(r.reason) == reasoncode:
            return True
        return False

    def matchContent(self, regex, attack=True):
        if attack:
            r = self.attackres
        else:
            r = self.rq
        if r is None:
            return
        # We may need to match multiline context in response body
        if re.search(regex, r.text, re.I):
            return True
        return False

    def identwaf(self, findall=False):
        detected = list()
        try:
            self.attackres, xurl = self.performCheck(self.centralAttack)
        except RequestBlocked:
            return detected, None

        for wafvendor in self.checklist:
            # logger.info('Checking for %s' % wafvendor)
            if self.wafdetections[wafvendor](self):
                detected.append(wafvendor)
                if not findall:
                    break
        self.knowledge['wafname'] = detected
        self.attackres.close()
        return detected, xurl


def buildResultRecord(url, waf, evil_url=None, alive=True):
    result = {}
    result['url'] = url
    if waf:
        result['detected'] = True
        if waf == 'generic':
            result['trigger_url'] = evil_url
            result['firewall'] = 'Generic'
            result['manufacturer'] = 'Unknown'
        else:
            result['trigger_url'] = evil_url
            result['firewall'] = waf.split('(')[0].strip()
            result['manufacturer'] = waf.split('(')[1].replace(')', '').strip()
    else:
        if alive:
            result['trigger_url'] = evil_url
            result['detected'] = False
            result['firewall'] = None
            result['manufacturer'] = None
        else:
            result['trigger_url'] = None
            result['detected'] = None
            result['firewall'] = None
            result['manufacturer'] = None
    return result


def getTextResults(res=None):
    # leaving out some space for future possibilities of newer columns
    # newer columns can be added to this tuple below
    keys = ('detected')
    res = [({key: ba[key] for key in ba if key not in keys}) for ba in res]
    rows = []
    for dk in res:
        p = [str(x) for _, x in dk.items()]
        rows.append(p)
    for m in rows:
        m[1] = '%s (%s)' % (m[1], m[2])
        m.pop()
    defgen = [
        (max([len(str(row[i])) for row in rows]) + 3)
        for i in range(len(rows[0]))
    ]
    rwfmt = "".join(["{:>" + str(dank) + "}" for dank in defgen])
    textresults = []
    for row in rows:
        textresults.append(rwfmt.format(*row))
    return textresults


def create_random_param_name(size=8, chars=string.ascii_lowercase):
    return ''.join(random.choice(chars) for _ in range(size))


class RequestBlocked(Exception):
    pass


class WafCheck(object):
    def __init__(self):
        self.results = []

    def check_url(self, url):
        extraheaders = {}
        proxies = {}
        attacker = WAFW00F(url, followredirect=True, extraheaders=extraheaders,
                           proxies=proxies)
        if attacker.rq is None:
            logger.debug(f'{url} appears to be down')
            result = buildResultRecord(url, waf=None, evil_url=None, alive=False)
            self.results.append(result)
            attacker.session.close()
            return

        waf, xurl = attacker.identwaf(findall=False)

        if len(waf) > 0:
            for one_waf in waf:
                result = buildResultRecord(url, one_waf, xurl)
                self.results.append(result)
                attacker.session.close()
                return
        else:
            generic_url = attacker.genericdetect()
            if generic_url:
                result = buildResultRecord(url, 'generic', generic_url)
                self.results.append(result)
                attacker.session.close()
                return
            else:
                result = buildResultRecord(url, None, None)
                self.results.append(result)
                attacker.session.close()
                return

    def scan_gevent(self, urls):
        logger.info(f"scan_gevent start")
        pool = Pool()

        logger.info(f"init pools done")
        tasks = []
        for url in urls:
            task = pool.spawn(self.check_url, url)
            tasks.append(task)
        start_time = int(time.time())
        logger.info(f"spawn task done, Task count : {len(tasks)}")
        gevent.joinall(tasks)
        logger.info(f"Scan finish, Task count : {len(tasks)} Time use : {int(time.time() - start_time)}")
