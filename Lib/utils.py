from urllib.parse import urlparse

import requests

from Lib.log import logger

UA = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"


def http_req(url, method='get', **kwargs):
    kwargs.setdefault('verify', False)
    kwargs.setdefault('timeout', (10.1, 30.1))
    kwargs.setdefault('allow_redirects', False)

    headers = kwargs.get("headers", {})
    headers.setdefault("User-Agent", UA)
    # 不允许缓存
    headers.setdefault("Cache-Control", "max-age=0")

    kwargs["headers"] = headers

    # if Config.PROXY_URL:
    #     proxies['https'] = Config.PROXY_URL
    #     proxies['http'] = Config.PROXY_URL
    #     kwargs["proxies"] = proxies

    conn = getattr(requests, method)(url, **kwargs)

    return conn


def urlParser(target):
    ssl = False
    o = urlparse(target)
    if o[0] not in ['http', 'https', '']:
        logger.error('scheme %s not supported' % o[0])
        return
    if o[0] == 'https':
        ssl = True
    if len(o[2]) > 0:
        path = o[2]
    else:
        path = '/'
    tmp = o[1].split(':')
    if len(tmp) > 1:
        port = tmp[1]
    else:
        port = None
    hostname = tmp[0]
    query = o[4]
    return (hostname, port, path, query, ssl)
