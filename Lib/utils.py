import requests

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
