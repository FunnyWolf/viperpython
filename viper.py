#!/usr/bin/python3.7
# -*- coding: utf-8 -*-

import argparse
import os
import shutil
import socket
import subprocess
import time

LOCALHOST = "127.0.0.1"
nginx_port = 60000
viper_port = 60002
daphne_port = 60003
redis_port = 60004
msgrpc_port = 60005
LOGDIR = "/root/viper/Docker/log"
devNull = open(os.devnull, 'w')


def check_services():
    """服务检查函数"""
    all_start = True
    print("-------------- 检查服务状态 ----------------")
    print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))
    redis_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    redis_client.settimeout(1)
    try:
        redis_client.connect((LOCALHOST, redis_port))
        print("[+] redis运行中")
        redis_client.close()
    except Exception as _:
        all_start = False
        print("[x] redis未启动")
    finally:
        redis_client.close()

    nginx_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    nginx_client.settimeout(1)
    try:
        nginx_client.connect((LOCALHOST, nginx_port))
        print("[+] nginx运行中")
        nginx_client.close()
    except Exception as _:
        all_start = False
        print("[x] nginx未启动")
    finally:
        nginx_client.close()

    msf_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    msf_client.settimeout(1)
    try:
        msf_client.connect((LOCALHOST, msgrpc_port))
        print("[+] msfrpcd运行中")
        msf_client.close()
    except Exception as _:
        all_start = False
        print("[x] msfrpcd未启动")
    finally:
        msf_client.close()

    uwsgi_addr = '/root/viper/uwsgi.sock'
    viper_client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        viper_client.connect(uwsgi_addr)
        print("[+] VIPER主服务运行中")
        viper_client.close()
    except Exception as _:
        all_start = False
        print("[x] VIPER主服务未启动")
    finally:
        viper_client.close()

    daphne_addr = '/root/viper/daphne.sock'
    daphne_client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        daphne_client.connect(daphne_addr)
        print("[+] daphne服务运行中")
        daphne_client.close()
    except Exception as _:
        all_start = False
        print("[x] daphne主服务未启动")
    finally:
        daphne_client.close()
    return all_start


def init_copy_file():
    if not os.path.exists("/root/viper/Docker/db/db.sqlite3"):
        src_file = "/root/viper/Docker/db_empty.sqlite3"
        target_path = "/root/viper/Docker/db/db.sqlite3"
        shutil.copy(src_file, target_path)
    for root, dirs, files in os.walk("/root/viper/Docker/loot"):
        for file in files:
            src_file = os.path.join("/root/viper/Docker/loot", file)
            target_path = os.path.join("/root/.msf4/loot", file)
            if not os.path.exists(target_path):
                shutil.copy(src_file, target_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="脚本用于 启动/停止 VIPER,修改root用户密码,设置反向Shell回连IP等功能.")
    parser.add_argument('action', nargs='?', metavar='start/stop/check', help="启动/停止/检测 VIPER服务", type=str)
    parser.add_argument('-pw', metavar='newpassword', help="修改root密码")

    args = parser.parse_args()

    action = args.action
    newpassword = args.pw

    if action is None and newpassword is None:
        parser.print_help()
        exit(0)

    # 初始化系统初始文件
    init_copy_file()

    if newpassword is not None:
        if len(newpassword) < 8:
            print("[x] 新密码必须大于等于8位")
            exit(0)
        else:
            # 启动django项目
            os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Viper.settings")
            import django

            django.setup()
            # 设置密码
            from django.contrib.auth.models import User

            user = User.objects.get(username='root')
            user.set_password(newpassword)
            user.save()
            # 清理已有token
            from rest_framework.authtoken.models import Token

            Token.objects.all().delete()
            print("[+] 修改密码完成,新密码为: {}".format(newpassword))

    if action is not None:
        if action.lower() == "start":

            # 启动服务
            # redis
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(1)
                client.connect((LOCALHOST, redis_port))
                print("[+] redis运行中")
                client.close()
            except Exception as err:
                print("[*] 启动redis服务")
                result = subprocess.run(
                    ["service", "redis-server", "start"],
                    stdout=devNull,
                    stderr=devNull
                )

            # msfrpcd
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(1)
                client.connect((LOCALHOST, msgrpc_port))
                print("[+] msfrpcd运行中")
                client.close()
            except Exception as err:
                print("[*] 启动msfrpcd服务")
                res = subprocess.Popen(
                    f"nohup puma -b tcp://127.0.0.1:{msgrpc_port} -e production --pidfile /root/viper/puma.pid "
                    f"--redirect-stdout {LOGDIR}/puma.log --redirect-stderr {LOGDIR}/puma.log /root/metasploit-framework/msf-json-rpc.ru &",
                    shell=True,
                    stdout=devNull,
                    stderr=devNull
                )

            # daphne
            try:
                serverAddr = '/root/viper/daphne.sock'
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(serverAddr)
                print("[+] daphne服务运行中")
                client.close()
            except Exception as err:
                print("[*] 启动daphne主服务")
                os.chdir("/root/viper/")
                subprocess.Popen(
                    "rm /root/viper/daphne.sock.lock", shell=True,
                    stdout=devNull,
                    stderr=devNull
                )
                subprocess.Popen(
                    "rm /root/viper/daphne.sock", shell=True,
                    stdout=devNull,
                    stderr=devNull
                )
                res = subprocess.Popen(
                    f"nohup daphne -u /root/viper/daphne.sock --access-log {LOGDIR}/daphne.log Viper.asgi:application &",
                    shell=True,
                    stdout=devNull,
                    stderr=devNull
                )

            # viper
            try:
                serverAddr = '/root/viper/uwsgi.sock'
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(serverAddr)
                print("[+] VIPER主服务运行中")
                client.close()
            except Exception as err:
                print("[*] 启动VIPER主服务")
                result = subprocess.run(
                    ["uwsgi", "--ini", "/root/viper/uwsgi.ini", ],
                    stdout=devNull,
                    stderr=devNull
                )

            # nginx
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(1)
                client.connect((LOCALHOST, nginx_port))
                print("[+] nginx运行中")
                client.close()
            except Exception as err:
                print("[*] 启动nginx服务")
                result = subprocess.run(
                    ["service", "nginx", "start"],
                    stdout=devNull,
                    stderr=devNull
                )

            for i in range(6):
                time.sleep(5)
                if check_services():
                    print("[+] 启动完成")
                    break

            # 不要删除这个死循环,此循环是确保docker-compose后台运行基础
            while True:
                time.sleep(60)
                check_services()

        elif action.lower() == "stop":

            # 停止服务
            try:
                print("[*] 关闭nginx服务")
                result = subprocess.run(["service", "nginx", "stop"], stdout=devNull)
            except Exception as E:
                pass

            try:
                print("[*] 关闭msfrpcd服务")
                subprocess.run(
                    ["/sbin/start-stop-daemon", "--quiet", "--stop", "--retry", "QUIT/5", "--pidfile",
                     "/root/puma.pid"],
                    stdout=devNull,
                    stderr=devNull
                )
                subprocess.Popen(
                    "kill -9 $(ps aux | grep puma | tr -s ' '| cut -d ' ' -f 2)", shell=True,
                    stdout=devNull,
                    stderr=devNull
                )
                subprocess.Popen(
                    "rm /root/puma.pid", shell=True,
                    stdout=devNull,
                    stderr=devNull
                )
            except Exception as E:
                pass

            try:
                print("[*] 关闭VIPER主服务")
                subprocess.run(
                    ["uwsgi", "--stop", "/root/viper/uwsgi.pid"],
                    stdout=devNull,
                    stderr=devNull
                )
                subprocess.Popen(
                    "kill -9 $(ps aux | grep uwsgi | tr -s ' '| cut -d ' ' -f 2)", shell=True,
                    stdout=devNull,
                    stderr=devNull
                )
                subprocess.Popen(
                    "rm /root/viper/uwsgi.pid", shell=True,
                    stdout=devNull,
                    stderr=devNull
                )
            except Exception as E:
                pass

            try:
                print("[*] 关闭daphne服务")
                subprocess.Popen(
                    "kill -9 $(ps aux | grep daphne | tr -s ' '| cut -d ' ' -f 2)", shell=True,
                    stdout=devNull,
                    stderr=devNull
                )
                subprocess.Popen(
                    "rm /root/viper/daphne.sock.lock", shell=True,
                    stdout=devNull,
                    stderr=devNull
                )
                subprocess.Popen(
                    "rm /root/viper/daphne.sock", shell=True,
                    stdout=devNull,
                    stderr=devNull
                )
            except Exception as E:
                pass
            time.sleep(5)
            check_services()
            exit(0)
        else:
            check_services()
