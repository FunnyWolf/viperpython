import json
import re
import time
from urllib.parse import urlencode

import requests

from Lib.log import logger
from Lib.xcache import Xcache
from WebDatabase.Interface.dataset import DataSet
from WebDatabase.documents import CompanyAPPDocument, CompanyICPDocument, CompanyWechatDocument, ClueCompanyDocument


class Aiqicha(object):
    def __init__(self):
        self.cookie = None
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36 Edg/98.0.1108.43',
            'Accept': "text/html, application/xhtml+xml, image/jxr, */*",
            "Cookie": self.cookie,
            "Referer": 'https://aiqicha.baidu.com/'
        }

    def set_cookie(self, cookie):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36 Edg/98.0.1108.43',
            'Accept': "text/html, application/xhtml+xml, image/jxr, */*",
            "Cookie": cookie,
            "Referer": 'https://aiqicha.baidu.com/'
        }

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
            self.set_cookie(conf.get("cookie"))
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
        if pageCount == 0:
            return []
        elif pageCount == 1:
            if data.get("list") is not None:
                return data.get("list")
            else:
                return []
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
                if response_json.get("data").get("list"):
                    result_list.extend(response_json.get("data").get("list"))
            return result_list

    def get_icp_by_pid(self, company_base_info):
        api = "detail/icpinfoAjax"
        url = f"https://aiqicha.baidu.com/{api}?pid={company_base_info.pid}"
        result_list = self.get_muitpage_data(url)
        icp_list = []
        for one in result_list:
            domain_list = one.get("domain")
            for one_domain in domain_list:
                company_icp = CompanyICPDocument()
                company_icp.company_name = company_base_info.company_name
                company_icp.pid = company_base_info.pid
                company_icp.domain = one_domain
                company_icp.homeSite = one.get("homeSite")[0]
                company_icp.icpNo = one.get("icpNo")
                company_icp.siteName = one.get("siteName")

                company_icp.source = "Aiqicha"
                company_icp.update_time = int(time.time())
                company_icp.data = one

                icp_list.append(company_icp)
        return icp_list

    def get_app_by_pid(self, company_base_info):
        api = "c/appinfoAjax"
        url = f"https://aiqicha.baidu.com/{api}?pid={company_base_info.pid}"
        result_list = self.get_muitpage_data(url)
        app_list = []
        for one in result_list:
            company_app = CompanyAPPDocument()
            company_app.company_name = company_base_info.company_name
            company_app.pid = company_base_info.pid
            company_app.name = one.get("name")
            company_app.classify = one.get("classify")
            company_app.logo = one.get("logo")
            company_app.logoBrief = one.get("logoBrief")

            company_app.source = "Aiqicha"
            company_app.update_time = int(time.time())
            company_app.data = one

            app_list.append(company_app)
        return app_list

    def get_wechat_by_pid(self, company_base_info):
        api = "c/wechatoaAjax"
        url = f"https://aiqicha.baidu.com/{api}?pid={company_base_info.pid}"
        result_list = self.get_muitpage_data(url)
        wechat_list = []
        for one in result_list:
            company_wechat = CompanyWechatDocument()
            company_wechat.company_name = company_base_info.company_name
            company_wechat.pid = company_base_info.pid
            company_wechat.principalName = one.get("principalName")
            company_wechat.wechatId = one.get("wechatId")
            company_wechat.wechatName = one.get("wechatName")
            company_wechat.wechatIntruduction = one.get("wechatIntruduction")
            company_wechat.wechatLogo = one.get("wechatLogo")
            company_wechat.qrcode = one.get("qrcode")

            company_wechat.source = 'Aiqicha'
            company_wechat.update_time = int(time.time())
            company_wechat.data = one

            wechat_list.append(company_wechat)
        return wechat_list

    def suggest_by_keyword(self, keyword):
        url = f"https://aiqicha.baidu.com/index/suggest"
        data = {'q': keyword, 't': 0}
        self.headers["Content-Type"] = "application/x-www-form-urlencoded"
        response = requests.post(url, data=urlencode(data), headers=self.headers)
        data = response.json()
        if data.get("status") == 0:
            if data.get("data") is not None:
                return data.get("data").get("queryList")

    def search_by_name(self, company_name, dataset: DataSet):
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
                clue_company = ClueCompanyDocument()

                clue_company.company_name = one_result.get("titleName")
                clue_company.pid = one_result.get("pid")
                clue_company.entType = one_result.get("entType")
                clue_company.validityFrom = one_result.get("validityFrom")
                clue_company.legalPerson = one_result.get("legalPerson")
                clue_company.openStatus = one_result.get("openStatus")
                clue_company.logoWord = one_result.get("logoWord")
                clue_company.titleName = one_result.get("titleName")
                clue_company.titleDomicile = one_result.get("titleDomicile")
                clue_company.regCap = one_result.get("regCap")
                clue_company.regNo = one_result.get("regNo")
                clue_company.email = one_result.get("email")
                clue_company.website = one_result.get("website")
                clue_company.scope = one_result.get("scope")
                clue_company.telephone = one_result.get("telephone")

                clue_company.source = 'Aiqicha'
                clue_company.update_time = int(time.time())
                clue_company.data = one_result

                dataset.companyBaseInfoList.append(clue_company)

                dataset.companyICPList.extend(self.get_icp_by_pid(clue_company))
                dataset.companyAPPList.extend(self.get_app_by_pid(clue_company))
                dataset.companyWechatList.extend(self.get_wechat_by_pid(clue_company))

                logger.info(f"{clue_company.titleName} {clue_company.pid} finish")

            return dataset
        else:
            raise Exception("Aiqicha Cookie expire")
