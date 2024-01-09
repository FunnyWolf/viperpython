import json
import re

import requests

from Lib.log import logger
from Lib.xcache import Xcache


# cookie = 'BIDUPSID=B27E39F5C4C83D7269311C58848B699C; PSTM=1633444694; BAIDUID=69B77A0A9B70611377416217CF19079C:SL=0:NR=10:FG=1; BAIDUID_BFESS=69B77A0A9B70611377416217CF19079C:SL=0:NR=10:FG=1; BAIDU_WISE_UID=wapp_1693019547852_147; H_PS_PSSID=39635_39648_39668_39663_39694_39676_39678_39713_39739_39764_39780_39790; MCITY=-58%3A; BDUSS=hWMGxIOU1WT3RFb0xVcWpCUTF5U1k5UElqQ3l5dFdWY2RxM0ZYbTNYN2U2YTFsRVFBQUFBJCQAAAAAAAAAAAEAAACYqpgheXUwODEwMjAzNgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAN5chmXeXIZlS0; BDUSS_BFESS=hWMGxIOU1WT3RFb0xVcWpCUTF5U1k5UElqQ3l5dFdWY2RxM0ZYbTNYN2U2YTFsRVFBQUFBJCQAAAAAAAAAAAEAAACYqpgheXUwODEwMjAzNgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAN5chmXeXIZlS0; ZFY=myVlSoSLJhIM:AATv86GKEiMwTkEBkISTc0PHdDy1BRE:C; arialoadData=false; BDPPN=fad540ad78da28a1f1c44a8ce9a3d2f7; login_type=passport; _t4z_qc8_=xlTM-TogKuTwsiJ1c10BF4DdC213emORKgmd; Hm_lvt_ad52b306e1ae4557f5d3534cce8f8bbf=1704531481; log_guid=484753b1f0e8cc299b6cbc33652c54a4; log_first_time=1704531481525; _j47_ka8_=57; _fb537_=xlTM-TogKuTwvwyBPglqclEglSrxsFZiaj8sEMAtD12dc%2Ah%2A3%2A%2AxrXomd; ab170452800=11d2bcc7c5bbd4d9ef2b63cf006be96517045315501c6; ab170453160=14d2bcc7c5bbd4d9ef2b63cf006be96517045320332c6; Hm_lpvt_ad52b306e1ae4557f5d3534cce8f8bbf=1704532033; ab_sr=1.0.1_MGMzNzJlMjljNTE4ZDQ4OWFjYWZmMzM0MmE1YWViZTU2MWY3YzhiZjY5MDk0MTM2YTkzZmMzZGEzNWQ1NmJhODdjMzhmZTlmNWEzZGQ1ZjY2ZWNkMDI1NThiNTc3OGY4MmI3OGI3MTYxZThkZjI0NTNmM2ZhMmUzYWQ2MWU3MmY0YWVkN2ZlYjZkYTc3ZDE0YzgzZTRmYzg3ZDZjZmNmNw==; _s53_d91_=1da957089c9edb3f74da4674afe3b82d70a087862ab6b4ef28047764f23e15a43f09a65373d684fd4b50fabbb8e0eed9e3322bd4388face83ee6d0a3d6f91dfd2be0a1e1cb70bb53a16b005d9bbe35839c03ae1eb3d72cab102a65d25da1b7acfed7273b75d7b137c5b99e1be8ab8e95397ca1cf61fb57766173498a2307c0ab421e58ce1988fe67e7e59aed957c3487d78bcb040880e57ee6eba562c442ce4937003a0b71b8215e0a8f2016eb96287dd4e881fe51bd7b0af969bad30a42cc176f43e6bcc2e857510d3dbeefccc179efe81357dc8504e2c11091700e35983e63; _y18_s21_=66315b3d; log_last_time=1704532069144; RT="z=1&dm=baidu.com&si=75665bd6-aa8c-43e4-a34c-b3e661ecafbf&ss=lr1u17de&sl=9&tt=92r&bcn=https%3A%2F%2Ffclog.baidu.com%2Flog%2Fweirwood%3Ftype%3Dperf&ld=1kxm&ul=cshv"'


class CompanyBaseInfo(object):
    def __init__(self):
        self.pid = None
        self.entType = None
        self.validityFrom = None
        self.openStatus = None  # "注销" "吊销"
        self.legalPerson = None
        self.logoWord = None
        self.titleName = None
        self.titleDomicile = None
        self.regCap = None
        self.regNo = None
        self.email = None
        self.website = None
        self.scope = None
        self.telephone = None

        self.icp = []
        self.app = []
        self.wechat = []


class CompanyICP(object):
    def __init__(self):
        self.domain = []
        self.homeSite = []
        self.icpNo = None
        self.siteName = None


class CompanyAPP(object):
    def __init__(self):
        self.name = None
        self.classify = None
        self.logo = None
        self.logoBrief = None


class CompanyWechat(object):
    def __init__(self):
        self.principalName = None
        self.wechatId = None
        self.wechatName = None
        self.wechatIntruduction = None
        self.wechatLogo = None
        self.qrcode = None


class Aiqicha(object):
    def __init__(self):
        self.cookie = None
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36 Edg/98.0.1108.43',
            'Accept': "text/html, application/xhtml+xml, image/jxr, */*",
            "Cookie": self.cookie,
            "Referer": 'https://aiqicha.baidu.com/'
        }

    # def get_en_info_by_pid(self, company_base_info):
    #     url = f"https://aiqicha.baidu.com/compdata/navigationListAjax?pid={company_base_info.pid}"
    #     response = requests.get(url, headers=self.headers)
    #     try:
    #         response_json = response.json()
    #     except Exception as E:
    #         raise Exception(f"Aiqicha {url} error")
    #     if response_json.get("status") != 0:
    #         return None
    #     data = response_json.get("data")
    #     for x in data:
    #         # 获取备案信息
    #         if x.get("id") == 'certRecord':
    #             children = x.get("children")
    #             for y in children:
    #                 if y.get("id") == "webRecord":
    #                     company_base_info.webRecordTotal = y.get("total")

    def set_cookie(self, cookie):
        self.cookie = cookie

    def is_alive(self):
        url = f"https://aiqicha.baidu.com/usercenter/getvipinfoAjax"
        response = requests.get(url, headers=self.headers)

        try:
            data = response.json()
            if data.get("status") == 0:
                if data.get("data").get("vip") is not None:
                    return True
        except Exception as E:
            logger.exception(E)
            return False
        return False

    def init_conf_from_cache(self):
        conf = Xcache.get_aiqicha_conf()
        if conf.get("alive") is not True:
            return False
        else:
            self.key = conf.get("key")
            return True

    def get_muitpage_data(self, url):
        response = requests.get(url, headers=self.headers)
        try:
            response_json = response.json()
        except Exception as E:
            raise Exception(f"Aiqicha {url} error")
        if response_json.get("status") != 0:
            raise Exception(f"Aiqicha {url} status error")
        data = response_json.get("data")
        pageCount = data.get('pageCount')
        if pageCount == 1:
            return data.get("list")
        else:
            result_list: list = data.get("list")
            for i in range(2, pageCount + 1):
                page_url = f"{url}&p={i}"
                response = requests.get(page_url, headers=self.headers)
                try:
                    response_json = response.json()
                except Exception as E:
                    break
                if response_json.get("status") != 0:
                    break
                result_list.extend(response_json.get("data").get("list"))
            return result_list

    def get_icp_by_pid(self, company_base_info):
        api = "detail/icpinfoAjax"
        url = f"https://aiqicha.baidu.com/{api}?pid={company_base_info.pid}"
        result_list = self.get_muitpage_data(url)
        if result_list is None:
            return
        icp_list = []
        for one in result_list:
            company_icp = CompanyICP()
            company_icp.domain = one.get("domain")
            company_icp.homeSite = one.get("homeSite")
            company_icp.icpNo = one.get("icpNo")
            company_icp.siteName = one.get("siteName")
            icp_list.append(company_icp)
        company_base_info.icp = icp_list

    def get_app_by_pid(self, company_base_info):
        api = "c/appinfoAjax"
        url = f"https://aiqicha.baidu.com/{api}?pid={company_base_info.pid}"
        result_list = self.get_muitpage_data(url)
        app_list = []
        for one in result_list:
            company_app = CompanyAPP()
            company_app.name = one.get("name")
            company_app.classify = one.get("classify")
            company_app.logo = one.get("logo")
            company_app.logoBrief = one.get("logoBrief")
            app_list.append(company_app)
        company_base_info.app = app_list

    def get_wechat_by_pid(self, company_base_info):
        api = "c/wechatoaAjax"
        url = f"https://aiqicha.baidu.com/{api}?pid={company_base_info.pid}"
        result_list = self.get_muitpage_data(url)
        wechat_list = []
        for one in result_list:
            company_wechat = CompanyWechat()
            company_wechat.principalName = one.get("principalName")
            company_wechat.wechatId = one.get("wechatId")
            company_wechat.wechatName = one.get("wechatName")
            company_wechat.wechatIntruduction = one.get("wechatIntruduction")
            company_wechat.wechatLogo = one.get("wechatLogo")
            company_wechat.qrcode = one.get("qrcode")
            wechat_list.append(company_wechat)
        company_base_info.wechat = wechat_list

    def search_by_name(self, company_name):
        company_base_info_list = []
        url = f"https://aiqicha.baidu.com/s?q={company_name}&t=0"
        response = requests.get(url, headers=self.headers)
        pattern = re.compile(r'window\.pageData = (.*});')
        match = pattern.search(response.text)
        if match:
            data = match.group(1)
            data = data.replace("\n", "")
            data = data.replace(" ", "")
            try:
                data = json.loads(data)
                resultList = data.get("result").get("resultList")
            except Exception as E:
                raise Exception("Aiqicha Cookie expire")
            for one_result in resultList:
                company_base_info = CompanyBaseInfo()
                company_base_info.pid = one_result.get("pid")
                company_base_info.entType = one_result.get("entType")
                company_base_info.validityFrom = one_result.get("validityFrom")
                company_base_info.legalPerson = one_result.get("legalPerson")
                company_base_info.openStatus = one_result.get("openStatus")
                company_base_info.logoWord = one_result.get("logoWord")
                company_base_info.titleName = one_result.get("titleName")
                company_base_info.titleDomicile = one_result.get("titleDomicile")
                company_base_info.regCap = one_result.get("regCap")
                company_base_info.regNo = one_result.get("regNo")
                company_base_info.email = one_result.get("email")
                company_base_info.website = one_result.get("website")
                company_base_info.scope = one_result.get("scope")
                company_base_info.telephone = one_result.get("telephone")
                self.get_icp_by_pid(company_base_info)
                self.get_app_by_pid(company_base_info)
                self.get_wechat_by_pid(company_base_info)
                company_base_info_list.append(company_base_info)
                print(f"finish {company_base_info.titleName} {company_base_info.pid}")
            return company_base_info_list
        else:
            raise Exception("Aiqicha Cookie expire")
