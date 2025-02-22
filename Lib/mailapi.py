# -*- coding: utf-8 -*-
# @File  : fofaclient.py
# @Date  : 2021/2/25
# @Desc  :
import os
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import urllib3

from Lib.log import logger
from Lib.xcache import Xcache

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MailAPI(object):
    def __init__(self):
        self.smtp_server = None
        self.smtp_port = None
        self.ssl = None
        self.mail_account = None
        self.mail_password = None
        self.alive = False

    def init_by_config(self):
        conf = Xcache.get_smtp_conf()
        self.smtp_server = conf.get("smtp_server")
        self.smtp_port = conf.get("smtp_port")
        self.ssl = conf.get("ssl")
        self.mail_account = conf.get("mail_account")
        self.mail_password = conf.get("mail_password")
        return self.is_alive()

    def store_conf(self):
        conf = {
            "smtp_server": self.smtp_server,
            "smtp_port": self.smtp_port,
            "ssl": self.ssl,
            "mail_account": self.mail_account,
            "mail_password": self.mail_password,
            "alive": True
        }
        Xcache.set_smtp_conf(conf)

    def is_alive(self):
        try:
            if self.ssl:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            else:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.login(self.mail_account, self.mail_password)
            server.quit()
            return True, None
        except Exception as e:
            server.quit()
            return False, e

    def send_mail(self, mail_to, mail_subject, mail_content, mail_content_subtype="plain", attachments: list = []):
        # 创建MIME多部分消息对象
        message = MIMEMultipart()
        message['From'] = self.mail_account
        message['To'] = mail_to
        message['Subject'] = mail_subject

        # 添加邮件正文
        body = mail_content
        message.attach(MIMEText(body, mail_content_subtype))

        for attachment in attachments:
            attachment_bin = attachment.get("bin")
            attachment_filename = attachment.get("filename")
            basename, extension = os.path.splitext(attachment_filename)
            attachment1 = MIMEApplication(attachment_bin, _subtype=extension.lstrip('.'))
            attachment1.add_header('Content-Disposition', 'attachment', filename=attachment_filename)
            message.attach(attachment1)

        # 发送邮件
        try:
            if self.ssl:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            else:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.login(self.mail_account, self.mail_password)
            text = message.as_string()
            server.sendmail(self.mail_account, [mail_to], text)
            logger.info(f"邮件发送成功：{mail_subject} {mail_to}")
            server.quit()
            return True
        except Exception as e:
            server.quit()
            logger.exception(e)
            return False
