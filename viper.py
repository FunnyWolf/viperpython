#!/usr/bin/python3
# -*- coding: utf-8 -*-
import argparse
import logging
import os
import random
import re
import shutil
import socket
import string
import subprocess
import sys
import time
from logging.handlers import RotatingFileHandler

import redis
import yaml

LOCALHOST = "127.0.0.1"
msgrpc_port = 60005
mitmproxy_port = 28888
elasticsearch_port = 9200
LOGDIR = "/root/viper/Docker/log"
devNull = open(os.devnull, 'w')

log_file = os.path.join(LOGDIR, 'viper.log')
logger = logging.getLogger('viper')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(levelname)s][%(asctime)s][%(lineno)d] : %(message)s')

file_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
file_handler.setFormatter(formatter)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(stdout_handler)


def get_token():
    token = "foobared"
    try:
        with open('/root/.msf4/token.yml', 'r', encoding='utf-8') as f:
            token = yaml.load(f.read(), Loader=yaml.Loader).get("token")
    except Exception as E:
        logger.exception(E)
    return token


class RedisClient(object):

    def __init__(self):
        pass

    @staticmethod
    def get_result_connection():
        """用于订阅类操作,无需使用连接池"""
        REDIS_URL = f"unix://:{get_token()}@/var/run/redis/redis-server.sock?db="
        try:
            rcon = redis.Redis.from_url(url=f"{REDIS_URL}5")
            return rcon
        except Exception as E:
            logger.warning("redis连接失败")
            logger.exception(E)
            return None


def random_str(num):
    salt = ''.join(random.sample(string.ascii_letters, num))
    return salt


def get_nginx_port(false_exit=True):
    with open("/root/viper/Docker/nginxconfig/viper.conf") as f:
        data = f.read()
        result = re.search(r'listen (\d+);', data)
        if result is None:
            logger.error("viper.conf is not right,can not find like 'listen XXXXX;'")
            if false_exit:
                exit(1)
        else:
            if len(result.groups()) < 1:
                logger.error("viper.conf is not right,can not find like 'listen XXXXX;'")
                if false_exit:
                    exit(1)
            else:
                try:
                    nginx_port = int(result.group(1))
                    return nginx_port
                except Exception as E:
                    logger.error("viper.conf is not right,can not find like 'listen XXXXX;'")
                    if false_exit:
                        exit(1)


def restart_nginx():
    try:
        logger.warning("[*] 关闭nginx服务")
        result = subprocess.run(["nginx", "-s", "reload"], stdout=devNull)
        result = subprocess.run(["nginx", "-s", "reload"], stdout=devNull)
    except Exception as E:
        pass

    while True:
        try:
            nginx_port = get_nginx_port()
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(0.1)
            client.connect((LOCALHOST, nginx_port))
            logger.info("[+] nginx运行中")
            client.close()
            exit(0)
        except Exception as err:
            logger.info("[*] 启动nginx服务")
            result = subprocess.run(["service", "nginx", "start"], stdout=devNull, stderr=devNull)


def check_services():
    """服务检查函数"""
    nginx_port = get_nginx_port()
    all_start = True
    logger.info("-------------- 检查服务状态 ----------------")
    logger.info(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))

    # 检查redis
    redis_addr = '/var/run/redis/redis-server.sock'
    redis_client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        redis_client.connect(redis_addr)
        logger.info("[+] redis运行中")
        redis_client.close()
    except Exception as _:
        all_start = False
        logger.warning("[x] redis未启动")
    finally:
        redis_client.close()

    # elasticsearch
    elasticsearch_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elasticsearch_client.settimeout(0.1)
    try:
        elasticsearch_client.connect((LOCALHOST, elasticsearch_port))
        logger.info("[+] elasticsearch运行中")
        elasticsearch_client.close()
    except Exception as _:
        all_start = False
        logger.warning("[x] elasticsearch未启动")
    finally:
        elasticsearch_client.close()

    # nginx
    nginx_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    nginx_client.settimeout(0.1)
    try:
        nginx_client.connect((LOCALHOST, nginx_port))
        logger.info("[+] nginx运行中")
        nginx_client.close()
    except Exception as _:
        all_start = False
        logger.warning("[x] nginx未启动")
    finally:
        nginx_client.close()

    # 检查msfrpc
    msf_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    msf_client.settimeout(0.1)
    try:
        msf_client.connect((LOCALHOST, msgrpc_port))
        logger.info("[+] msfrpcd运行中")
        msf_client.close()
    except Exception as _:
        all_start = False
        logger.warning("[x] msfrpcd未启动")
    finally:
        msf_client.close()

    # 检查uwsgi
    uwsgi_addr = '/root/viper/uwsgi.sock'
    viper_client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        viper_client.connect(uwsgi_addr)
        logger.info("[+] uwsgi运行中")
        viper_client.close()
    except Exception as _:
        all_start = False
        logger.warning("[x] uwsgi未启动")
    finally:
        viper_client.close()

    # 检查daphne
    daphne_addr = '/root/viper/daphne.sock'
    daphne_client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        daphne_client.connect(daphne_addr)
        logger.info("[+] daphne服务运行中")
        daphne_client.close()
    except Exception as _:
        all_start = False
        logger.warning("[x] daphne主服务未启动")
    finally:
        daphne_client.close()
    return all_start


def check_nginx():
    nginx_port = get_nginx_port(false_exit=False)
    if nginx_port is None:
        return False

    # nginx
    nginx_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    nginx_client.settimeout(0.1)
    try:
        nginx_client.connect((LOCALHOST, nginx_port))
        logger.info("[+] nginx运行中")
        start_flag = True
    except Exception as _:
        start_flag = False
        logger.warning("[x] nginx未启动")
    finally:
        nginx_client.close()
    return start_flag


def check_elasticsearch():
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(1)
        client.connect((LOCALHOST, elasticsearch_port))
        client.close()
        return True
    except Exception as _:
        return False


def check_redis():
    rcon = RedisClient.get_result_connection()
    if rcon is None:
        return False
    try:
        rcon.set('foo', 'bar')
        return True
    except Exception as E:
        return False


def check_msfrpc():
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(0.5)
        client.connect((LOCALHOST, msgrpc_port))
        client.close()
        return True
    except Exception as err:
        # logger.exception(err)
        return False


def start_msfrpc():
    logger.info("[*] 启动msfrpcd服务")
    result = subprocess.run(["service", "puma", "start"], stdout=devNull, stderr=devNull)


def stop_services():
    # 停止服务
    try:
        logger.info("[*] 关闭nginx服务")
        result = subprocess.run(["service", "nginx", "stop"], stdout=devNull)
    except Exception as E:
        pass

    try:
        logger.info("[*] 关闭elasticsearch服务")
        command = 'kill -9 $(cat /var/run/elasticsearch/elasticsearch.pid)'
        result = subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=devNull)
        result = subprocess.run(["rm", "-f", "/var/run/elasticsearch/elasticsearch.pid"], stdout=devNull, stderr=devNull)
    except Exception as E:
        pass

    try:
        logger.info("[*] 关闭msfrpcd服务")
        result = subprocess.run(["service", "puma", "stop"], stdout=devNull, stderr=devNull)
    except Exception as E:
        pass

    try:
        logger.info("[*] 关闭VIPER主服务")
        subprocess.run(["uwsgi", "--stop", "/root/viper/uwsgi.pid"], stdout=devNull, stderr=devNull)
        subprocess.Popen("kill -9 $(ps aux | grep uwsgi | tr -s ' '| cut -d ' ' -f 2)", shell=True, stdout=devNull,
                         stderr=devNull)
        subprocess.Popen("rm /root/viper/uwsgi.pid", shell=True, stdout=devNull, stderr=devNull)
    except Exception as E:
        pass

    try:
        logger.info("[*] 关闭daphne服务")
        subprocess.Popen("kill -9 $(ps aux | grep daphne | tr -s ' '| cut -d ' ' -f 2)", shell=True, stdout=devNull,
                         stderr=devNull)
        subprocess.Popen("rm /root/viper/daphne.sock.lock", shell=True, stdout=devNull, stderr=devNull)
        subprocess.Popen("rm /root/viper/daphne.sock", shell=True, stdout=devNull, stderr=devNull)
    except Exception as E:
        pass

    try:
        logger.info("[*] 关闭proxy服务")
        subprocess.Popen("kill -9 $(ps aux | grep mitmdump | tr -s ' '| cut -d ' ' -f 2)", shell=True, stdout=devNull,
                         stderr=devNull)
    except Exception as E:
        pass

    time.sleep(5)
    check_services()


def write_token_to_config_file(token):
    """生成随机密码"""
    # 写入yml文件
    try:
        token_yml = f'token: "{token}"'
        with open("/root/.msf4/token.yml", "w+", encoding="utf-8") as f:
            f.write(token_yml)
        redis_yml = f'redis_password: "{token}"\nredis_sock: "/var/run/redis/redis-server.sock"'
        with open("/root/.msf4/redis.yml", "w+", encoding="utf-8") as f:
            f.write(redis_yml)
    except Exception as E:
        logger.error("写入token.yml失败")
        logger.exception(E)
        exit(1)

    # 写入redis配置文件
    try:
        requirepass = f"requirepass {token}"
        with open("/root/viper/Docker/redis.conf", "w+", encoding="utf-8") as f:
            f.write(requirepass)
    except Exception as E:
        logger.error("写入redis.conf失败")
        logger.exception(E)
        exit(1)

    logger.info("[*] token写入token.yml和redis.conf")


def set_elasticsearch_password(token):
    for i in range(5):
        # 修改elasicsearch密码
        command = f'printf "{token}\\n{token}" | /usr/share/elasticsearch/bin/elasticsearch-reset-password -b -i -u elastic'
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = result.stdout.decode()
        print("returncode:", result.returncode)
        # print("stdout:", stdout)
        # print("stderr:", result.stderr.decode())
        if "Password for the [elastic] user successfully reset." in stdout:
            logger.info("[*] elasticsearch passwd 已重置")
            break
        time.sleep(3)
    else:
        logger.info("[x] elasticsearch passwd 设置失败")
        exit(1)


def upgrade_version_adapt():
    """版本升级适配代码"""

    # 升级到1.6.0
    if os.path.exists("/root/viper/Docker/nginxconfig/gencert.sh"):  # 表示为1.5.30 版本之前
        # 拷贝默认nginx配置,防止nginx起不来
        try:
            src_file = "/root/viper/Docker/nginxconfig_default/viper_default.conf"
            target_path = "/root/viper/Docker/nginxconfig/viper.conf"
            shutil.copy(src_file, target_path)
        except Exception as _:
            pass

        # 清理无用的证书文件
        try:
            unuse_files = ["ca.crt", "ca.key", "ca.srl", "client.crt", "client.csr", "client.key", "client.pfx",
                           "gencert.sh", "server.csr"]

            for one in unuse_files:
                try:
                    os.remove(f"/root/viper/Docker/nginxconfig/{one}")
                except Exception as _:
                    pass
        except Exception as _:
            pass


def init_file():
    try:
        if not os.path.exists("/root/viper/Docker/db/db.sqlite3"):
            src_file = "/root/viper/Docker/db_empty.sqlite3"
            target_path = "/root/viper/Docker/db/db.sqlite3"
            shutil.copy(src_file, target_path)
        for root, dirs, files in os.walk("/root/viper/Docker/loot_default"):
            for file in files:
                src_file = os.path.join("/root/metasploit-framework/data/loot_default", file)
                target_path = os.path.join("/root/.msf4/loot", file)
                if not os.path.exists(target_path):
                    shutil.copy(src_file, target_path)
        for root, dirs, files in os.walk("/root/viper/Docker/nginxconfig_default"):
            for file in files:
                src_file = os.path.join("/root/viper/Docker/nginxconfig_default", file)
                target_path = os.path.join("/root/viper/Docker/nginxconfig", file)
                if not os.path.exists(target_path):
                    shutil.copy(src_file, target_path)
    except Exception as E:
        logger.exception(E)
        exit(1)

    # 强制替换
    src_file = "/root/viper/Docker/nginxconfig_default/nobody.sh"
    target_file = "/root/viper/Docker/nginxconfig/nobody.sh"
    try:
        shutil.copy(src_file, target_file)
    except shutil.SameFileError:
        pass

    src_file = "/root/viper/Docker/nginxconfig_default/viper_default.conf"
    target_file = "/root/viper/Docker/nginxconfig/viper_default.conf"
    try:
        shutil.copy(src_file, target_file)
    except shutil.SameFileError:
        pass

    # set elasticsearch owner
    command = f'chown elasticsearch:elasticsearch -R /var/lib/elasticsearch'
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    command = f'chmod 755 -R /var/lib/elasticsearch'
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def change_password(new_password):
    # 启动django项目
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Viper.settings")
    import django
    django.setup()

    # 设置密码
    from django.contrib.auth.models import User
    from Lib.xcache import Xcache
    from rest_framework.authtoken.models import Token

    user = User.objects.get(username='root')
    user.set_password(new_password)
    user.save()

    # 清理已有token
    Token.objects.all().delete()
    Xcache.set_bruteforce_flag(False)
    Xcache.reset_login_fail_count()
    logger.info(f"[+] 修改密码完成,新密码为: {new_password}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="脚本用于 启动/停止 VIPER,修改root用户密码,设置反向Shell回连IP等功能.")
    parser.add_argument('action', nargs='?', metavar='start/stop/check/init/restartnginx',
                        help="启动/停止/检测 VIPER服务", type=str)
    parser.add_argument('-pw', metavar='newpassword', help="修改root密码")

    args = parser.parse_args()

    action = args.action
    newpassword = args.pw

    if action is None and newpassword is None:
        parser.print_help()
        exit(0)

    if action is not None and action.lower() == "healthcheck":
        check_services()
        exit(0)

    if action is not None:
        if action.lower() == "init":  # 初始化处理

            # 升级适配代码
            upgrade_version_adapt()

            # 初始化系统初始文件 必须在修改密码之前,确保数据库文件已经初始化
            init_file()

            # 生成随机密码
            token = random_str(10)

            write_token_to_config_file(token)

            # redis
            logger.info("[*] 重启redis服务")
            while True:
                result = subprocess.run(["service", "redis-server", "stop"], stdout=devNull)
                if check_redis():
                    logger.info("[*] redis is running,continue stop it")
                    time.sleep(3)
                    continue
                else:
                    logger.info("[*] redis is stoped")
                    break

            while True:
                result = subprocess.run(["service", "redis-server", "start"], stdout=devNull)
                if check_redis():
                    logger.info("[*] redis is started")
                    break
                else:
                    logger.info("[*] redis not start")
                    time.sleep(3)
                    continue
            logger.info("[*] 重启redis完成")

            # elasticsearch
            for i in range(5):
                if check_elasticsearch():
                    logger.info("[+] elasticsearch运行中")
                    break
                else:
                    logger.info("[*] 启动elasticsearch服务")
                    result = subprocess.run(
                        ["sudo", "-u", "elasticsearch", "/usr/share/elasticsearch/bin/elasticsearch", "-d", "-p", "/var/run/elasticsearch/elasticsearch.pid"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    print("returncode:", result.returncode)
                    # print("stdout:", result.stdout.decode())
                    # print("stderr:", result.stderr.decode())
                    time.sleep(3)
            else:
                logger.error("[x] elasticsearch启动失败")
                exit(1)

            # 设置es密码,必须在es服务启动之后,uwsgi启动之前
            set_elasticsearch_password(token)

            # redis
            for i in range(5):
                if check_redis():
                    logger.info("[+] redis运行中")
                    break
                else:
                    logger.info("[*] 启动redis服务")
                    result = subprocess.run(["service", "redis-server", "start"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    print("returncode:", result.returncode)
                    # print("stdout:", result.stdout.decode())
                    # print("stderr:", result.stderr.decode())
                    time.sleep(3)
            else:
                logger.error("[x] redis启动失败,参考https://www.yuque.com/vipersec/install/py5fqc.")
                exit(1)

            # daphne
            try:
                serverAddr = '/root/viper/daphne.sock'
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(serverAddr)
                logger.info("[+] daphne服务运行中")
                client.close()
            except Exception as err:
                logger.info("[*] 启动daphne主服务")
                os.chdir("/root/viper/")
                subprocess.Popen("rm /root/viper/daphne.sock.lock", shell=True, stdout=devNull, stderr=devNull)
                subprocess.Popen("rm /root/viper/daphne.sock", shell=True, stdout=devNull, stderr=devNull)
                res = subprocess.Popen(
                    f"nohup daphne -u /root/viper/daphne.sock --access-log {LOGDIR}/daphne.log Viper.asgi:application &",
                    shell=True, stdout=devNull, stderr=devNull)

            # mitmproxy
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(0.1)
                client.connect((LOCALHOST, mitmproxy_port))
                logger.info("[+] mitmproxy运行中")
                client.close()
            except Exception as err:
                logger.info("[*] 启动mitmproxy服务")
                if newpassword is not None:
                    res = subprocess.Popen(
                        f"nohup /usr/bin/python3 /opt/mitmproxy/release/specs/mitmdump -s /root/viper/STATICFILES/Tools/proxyscan.py --ssl-insecure -p {mitmproxy_port} --proxyauth root:{newpassword} --set block_global=false&",
                        shell=True, stdout=devNull, stderr=devNull)
                    logger.info(f"[+] Mitmproxy: http://vpsip:28888")
                    logger.info(f"[+] root:{newpassword}")
                else:
                    newpassword = random_str(10)
                    res = subprocess.Popen(
                        f"nohup /usr/bin/python3 /opt/mitmproxy/release/specs/mitmdump -s /root/viper/STATICFILES/Tools/proxyscan.py --ssl-insecure -p {mitmproxy_port} --proxyauth root:{newpassword} --set block_global=false&",
                        shell=True, stdout=devNull, stderr=devNull)
                    logger.info(f"[+] mitmproxy: http://vpsip:28888")
                    logger.info(f"[+] root:{newpassword}")

            # viper
            try:
                serverAddr = '/root/viper/uwsgi.sock'
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(serverAddr)
                logger.info("[+] VIPER主服务运行中")
                client.close()
            except Exception as err:
                logger.info("[*] 启动VIPER主服务")
                result = subprocess.run(["uwsgi", "--ini", "/root/viper/Docker/uwsgi.ini", ], stdout=devNull, stderr=devNull)

            # Supervisor
            result = subprocess.run(['supervisord', '-c', '/etc/supervisor/supervisord.conf'], stdout=devNull, stderr=devNull)

            # nginx
            try:
                nginx_port = get_nginx_port()
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(1)
                client.connect((LOCALHOST, nginx_port))
                logger.info("[+] nginx运行中")
                client.close()
            except Exception as err:
                logger.info("[*] 启动nginx服务")
                result = subprocess.run(["service", "nginx", "start"], stdout=devNull, stderr=devNull)

            # msfrpcd
            for i in range(5):
                if check_msfrpc():
                    logger.info("[+] msfrpcd运行中")
                    break
                else:
                    start_msfrpc()
                    time.sleep(10)
            else:
                logger.error("[x] msfrpcd启动失败")
                exit(1)

            # 检查服务
            for i in range(10):
                time.sleep(6)
                if check_services():
                    logger.info("[+] viper启动完成")
                    break
            else:
                logger.error("[x] viper启动失败")
                exit(1)

            # 处理修改密码,必须在服务启动之后
            if newpassword is not None:
                try:
                    change_password(newpassword)
                except Exception as E:
                    logger.exception(E)
                    exit(1)

            # 不要删除这个死循环,此循环是确保docker-compose后台运行基础
            while True:
                time.sleep(60)

        elif action.lower() == "restartnginx":
            restart_nginx()
        else:
            check_services()
    else:
        # 启动后进入命令行修改密码场景
        if newpassword is not None:
            try:
                change_password(newpassword)
            except Exception as E:
                logger.exception(E)
