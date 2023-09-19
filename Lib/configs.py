# -*- coding: utf-8 -*-
# @File  : configs.py
# @Date  : 2019/1/11
# @Desc  : 存储viper通用的配置信息

CODE_MSG_ZH = {
    200: '服务器成功返回请求的数据',
    201: '新建或修改数据成功',
    202: '一个请求已经进入后台排队（异步任务）',
    204: '删除数据成功',
    400: '发出的请求有错误，服务器没有进行新建或修改数据的操作',
    401: '用户没有权限（令牌、用户名、密码错误）',
    403: '用户得到授权，但是访问是被禁止的',
    404: '发出的请求针对的是不存在的记录，服务器没有进行操作',
    405: '发送的新建请求失败,返回空数据',
    406: '请求的格式不可得',
    409: '请求的资源存在异常',
    410: '请求的资源被永久删除，且不会再得到的',
    422: '当创建一个对象时，发生一个验证错误',
    500: '服务器发生错误，请检查服务器',
    502: '网关错误',
    503: '服务不可用，服务器暂时过载或维护',
    504: '网关超时',

    # 自定义的错误码
    505: "MSFRPC调用失败",
}

CODE_MSG_EN = {
    200: "The server successfully returned the requested data. ",
    201: "New or modified data succeeded. ",
    202: "A request has entered the background queue (asynchronous task). ",
    204: "Data deleted successfully. ",
    400: "There was an error in the request. The server did not create or modify the data. ",
    401: "The user does not have permission (wrong token, user name, password). ",
    403: "The user is authorized, but access is forbidden. ",
    404: "The request is for a non-existent record, and the server has not operated. ",
    405: "The request method is not allowed. ",
    406: "The format of the request is not available. ",
    410: "The requested resource has been permanently deleted and will no longer be available. ",
    422: "A validation error occurred while creating an object. ",
    500: "An error occurred on the server, please check the server. ",
    502: "Gateway error. ",
    503: "The service is not available. The server is temporarily overloaded or maintained. ",
    504: "Gateway timed out. ",

    # 自定义的错误码
    505: "MSFRPC call failed",
}

BASEAUTH_MSG_ZH = {
    201: '登录成功',

    301: '登录失败,密码错误',
    302: '配置错误,VIPER不允许使用diypassword作为密码!',
}
BASEAUTH_MSG_EN = {
    201: 'Login successful',

    301: 'Login failed,password error',
    302: 'Configuration error, VIPER does not allow diypassword as a password!',
}

PORTFWD_MSG_ZH = {
    201: '新建端口转发成功',
    204: '删除端口转发成功',

    301: '无法创建转发,请确认服务器及目标主机端口未占用',
    302: '解析运行结果失败',
    305: '删除端口转发失败',
    306: '参数检查失败',
    307: '删除端口转发失败',
    308: 'MSFRPC调用失败',
}

PORTFWD_MSG_EN = {
    201: 'Create portfwd succeeded',
    204: 'Delete portfwd successfully',

    301: 'Unable to create portfwd, please confirm that the server and target host ports are not occupied',
    302: 'Failed to parse the result',
    305: 'Failed to delete portfwd',
    306: 'Parameter check failed',
    307: 'Failed to delete portfwd',
    308: 'MSFRPC call failed',
}

TRANSPORT_MSG_ZH = {
    201: "新增传输成功",
    202: "切换传输成功",
    203: "休眠命令发送成功",
    204: "删除传输成功",

    301: '添加传输失败,请选择其他监听',
    302: '切换传输失败',
    303: '无法解析所选监听参数,请选择其他监听',
    304: '删除传输失败',
    305: '休眠Session失败',
    306: '输入参数错误',
}

TRANSPORT_MSG_EN = {
    201: "Added transport successfully",
    202: "Switch transport succeeded",
    203: "Sleep command sent successfully",
    204: "Delete transport succeeded",

    301: 'Failed to add transport, please select another handler',
    302: 'Failed to switch transport',
    303: 'Unable to parse the selected handler parameters, please select another handler',
    304: 'Delete transport failed',
    305: 'Sleep Session failed',
    306: 'Input parameter error',
}

PostModuleActuator_MSG_ZH = {
    201: "新建后台任务成功",

    301: "模块前序检查失败,检查函数内部错误",
    305: "获取模块配置失败",
    306: "新建后台任务失败",
    307: "新建后台任务失败",
}

PostModuleActuator_MSG_EN = {
    201: "Create background task succeeded",

    301: "Module pre-check failed, check function internal error",
    305: "Failed to get module configuration",
    306: "Failed to create a new background task",
    307: "新建后台任务失败",
}

PostModuleAuto_MSG_ZH = {
    201: "新建自动执行配置成功",
    202: "修改自动执行配置成功",
    204: "删除自动执行配置成功",

    304: "删除自动执行配置失败",
    306: "新建自动执行配置失败",
}

PostModuleAuto_MSG_EN = {
    201: "Create automatic configuration succeeded",
    202: "Update automatic configuration succeeded",
    204: "The automatic configuration is deleted successfully",

    304: "Failed to delete automatic configuration",
    306: "Failed to create new automatic configuration",
}

ProxyHttpScan_MSG_ZH = {
    201: "新建被动扫描配置成功",
    204: "删除被动扫描配置成功",

    304: "删除被动扫描配置失败",
    306: "新建被动扫描配置失败",
}

ProxyHttpScan_MSG_EN = {
    201: "Create Passive scanning configuration succeeded",
    204: "The Passive scanning configuration is deleted successfully",

    304: "Failed to delete Passive scanning configuration",
    306: "Failed to create new Passive scanning configuration",
}

PostModuleConfig_MSG_ZH = {
    201: "重新加载所有模块成功",
}

PostModuleConfig_MSG_EN = {
    201: "Reload all modules successfully",
}

PostModuleResultHistory_MSG_ZH = {
    204: "删除历史记录成功",

    304: "输入参数错误",
}

PostModuleResultHistory_MSG_EN = {
    204: "Delete history record successfully",

    304: "Input parameter error",
}

Setting_MSG_ZH = {
    201: "获取chat_id列表成功",
    202: "设置Telegram通知成功",
    203: "设置DingDing通知成功",
    204: "设置Session监控成功",
    205: "设置回连地址成功",
    206: "设置FOFA API成功",
    207: "设置Server酱通知成功",
    208: "设置360Quake API成功",
    209: "设置自动编排配置成功",
    210: "下载日志文件成功",
    211: "设置被动扫描配置成功",
    212: "设置Zoomeye API成功",

    301: "未知配置类型",
    302: "解析配置参数失败",
    303: "输入的Telegram配置不可用,请检查token是否正确且网络可以访问telegram",
    304: "输入的DingDing配置不可用,请检查token是否正确且安全关键字是否正确",
    305: "输入的Server酱SendKey不可用,请检查SendKey是否正确",
    306: "输入的FOFA配置不可用,请检查email及key是否正确",
    307: "输入的360Quake配置不可用,请检查key是否正确",
    308: "输入的Zoomeye配置不可用,请检查key是否正确",
}

Setting_MSG_EN = {
    201: "Get the chat_id list successfully",
    202: "Set Telegram notification successfully",
    203: "Set DingDing notification successfully",
    204: "Session monitor is set successfully",
    205: "Set lhost successfully",
    206: "FOFA API set successfully",
    207: "Set ServerChan notification successfully",
    208: "Successfully set up 360Quake API",
    209: "The automatic arrangement configuration is set successfully",
    210: "Download logfile success",
    211: "Set Passive scanning conf success",
    212: "Successfully set up Zoomeye API",

    301: "Unknown configuration type",
    302: "Failed to parse configuration parameters",
    303: "The entered Telegram configuration is not available, please check whether the token is correct and the network can access telegram",
    304: "The entered DingDing configuration is not available, please check whether the token is correct and the keyword is correct",
    305: "The entered ServerChan SendKey is not available, please check whether the SendKey is correct",
    306: "The entered FOFA configuration is not available, please check if the email and key are correct",
    307: "The entered 360Quake configuration is not available, please check if the key is correct",
    308: "The entered Zoomeye configuration is not available, please check if the key is correct",
}

NetworkSearch_MSG_ZH = {
    201: "查询数据成功",

    301: "API接口调用失败,请确认搜索引擎配置是否正确",
    303: "查询接口异常",
    304: "无效的搜索引擎",
}

NetworkSearch_MSG_EN = {
    201: "Query data successfully",

    301: "API interface call failed, please confirm whether the search engine configuration is correct",
    303: "Query interface exception",
    304: "Invalid search engine",
}

Host_MSG_ZH = {
    201: "更新主机标签成功",
    202: "删除主机成功",

    301: "删除主机失败,此主机不存在",
    304: "主机不存在",
}

Host_MSG_EN = {
    201: "Host tag updated successfully",
    202: "Delete the host successfully",

    301: "Failed to delete the host, this host does not exist",
    304: "Host does not exist",
}

UUID_JSON_MSG_ZH = {
    202: "清理数据成功",
}

UUID_JSON_MSG_EN = {
    201: "Clean data successfully",
}

HostFile_MSG_ZH = {
    304: "请求文件不存在",
}

HostFile_MSG_EN = {
    304: "The requested file does not exist",
}
IPFilter_MSG_ZH = {
    201: "更新配置成功",
    202: "放行",
    203: "更新权限信息成功",

    302: "屏蔽",
    304: "输入参数错误",
}
IPFilter_MSG_EN = {
    201: "Update config successfully",
    202: "Pass",
    203: "Successfully updated session information",

    302: "Block",
    304: "Input parameter error",
}

Session_MSG_ZH = {
    201: "删除权限成功",
    202: "删除权限命令已发送",
    203: "更新权限信息成功",

    301: "删除权限异常",
    304: "输入参数错误",
}

Session_MSG_EN = {
    201: "Successfully deleted session",
    202: "Delete session command sent",
    203: "Successfully updated session information",

    301: "Delete session exception",
    304: "Input parameter error",
}

SessionIO_MSG_ZH = {
    200: "发送命令成功",
    201: "发送命令成功",
    202: "读取结果成功",
    203: "退出Session",
    204: "清空历史记录成功",

    303: "执行操作超时",
    305: "发送命令失败",
    306: "系统内部异常",
}

SessionIO_MSG_EN = {
    200: "Send the command successfully",
    201: "Send the command successfully",
    202: "Read the result successfully",
    203: "Exit Session",
    204: "Clear history record successfully",

    303: "Execution timeout",
    305: "Failed to send command",
    306: "Abnormal inside the system",
}

Socks_MSG_ZH = {
    201: "新建socks代理成功",
    204: "删除socks代理成功",

    303: "执行操作超时",
    304: "输入参数错误",
    305: "解析配置参数失败",
    306: "新建socks代理失败",
}

Socks_MSG_EN = {
    201: "Successfully created a new socks proxy",
    204: "Socks proxy deleted successfully",

    303: "Execution timeout",
    304: "Input parameter error",
    305: "Failed to parse configuration parameters",
    306: "Failed to create a new socks proxy",
}

Notice_MSG_ZH = {
    200: "发送消息成功",
    201: "清除通知成功",
    202: "发送消息成功",
}

Notice_MSG_EN = {
    200: "Message sent successfully",
    201: "Clear notification succeeded",
    202: "Message sent successfully",
}

FileMsf_MSG_ZH = {
    201: "上传文件成功",
    202: "删除文件成功",
    203: "下载文件成功",

    301: "文件不存在",
    302: "上传文件失败",
    303: "下载文件失败",
}

FileMsf_MSG_EN = {
    201: "File uploaded successfully",
    202: "File deleted successfully",
    203: "Download the file successfully",

    301: "File does not exist",
    302: "Failed to upload file",
    303: "Failed to download file",
}

FileSession_MSG_ZH = {
    201: "执行操作成功",
    202: "后台执行成功",
    203: "切换工作目录成功",
    204: "更新文件内容成功",

    301: "执行操作超时",
    302: "解析结果异常",
    303: "执行操作失败",
    306: "未知命令",
}

FileSession_MSG_EN = {
    201: "The operation was successful",
    202: "Successful background execution",
    203: "Successfully switched working directory",
    204: "Update file content successfully",

    301: "Execution timeout",
    302: "Parsing result is abnormal",
    303: "Failed to perform operation",
    306: "Unknown command",
}

Handler_MSG_ZH = {
    201: "新建监听成功",
    202: "删除监听成功",

    301: "新建监听超时",
    302: "新建监听失败",
    303: "输入参数错误",
    306: "端口已占用",
}

Handler_MSG_EN = {
    201: "Successfully created a handler",
    202: "Delete the handler successfully",

    301: "Create handler timeout",
    302: "Failed to create a new handler",
    303: "Input parameter error",
    306: "Port is occupied",
}

WebDelivery_MSG_ZH = {
    201: "新建WebDelivery成功",
    202: "删除WebDelivery成功",

    301: "新建WebDelivery超时",
    302: "新建WebDelivery失败",
    303: "输入参数错误",
    306: "端口已占用",
    307: "Target和载荷不匹配",
}

WebDelivery_MSG_EN = {
    201: "Create WebDelivery successfully",
    202: "Delete WebDelivery successfully",

    301: "Create WebDelivery timeout",
    302: "Failed to create new WebDelivery",
    303: "Input parameter error",
    306: "Port is occupied",
    307: "Target and Payload do not match",
}

Job_MSG_ZH = {
    204: "删除任务成功",

    301: "后台任务不存在",
    304: "后台任务不存在",
    305: "删除任务失败",
}

Job_MSG_EN = {
    204: "Successfully deleted task",

    301: "Background task does not exist",
    304: "Background task does not exist",
    305: "Failed to delete task",
}

Payload_MSG_ZH = {
    201: "生成载荷成功",

    305: "生成载荷失败",
    306: "multi类型监听无法自动生成载荷",
}

Payload_MSG_EN = {
    201: "Payload generated successfully",

    305: "Failed to generate payload",
    306: "Multi type handler cannot automatically generate payload",
}

Route_MSG_ZH = {
    201: "新增路由成功",
    204: "删除路由成功",

    304: "删除路由失败",
    305: "新增路由失败",
    306: "解析结果失败",
    307: "MSFRPC调用失败",
}

Route_MSG_EN = {
    201: "Add route successfully",
    204: "Delete route successfully",

    304: "Failed to delete route",
    305: "Failed to add route",
    306: "Failed to parse the result",
    307: "MSFRPC call failed",
}

Credential_MSG_ZH = {
    201: "新增凭证成功",
    202: "更新凭证说明成功",
    204: "删除凭证成功",

    304: "输入参数错误",
}

Credential_MSG_EN = {
    201: "Successfully added certificate",
    202: "Update of credentials note successfully",
    204: "Credentials deleted successfully",

    304: "Input parameter error",
}

PortService_MSG_ZH = {
    204: "删除端口信息成功",

    304: "输入参数错误",
}

PortService_MSG_EN = {
    204: "Successfully delete port information",

    304: "Input parameter error",
}

Vulnerability_MSG_ZH = {
    204: "删除漏洞信息成功",

    304: "输入参数错误",
}

Vulnerability_MSG_EN = {
    204: "Vulnerability information deleted successfully",

    304: "Input parameter error",
}

LazyLoader_MSG_ZH = {
    201: "更新配置成功",
    202: "删除配置成功",
    203: "正在下载示例代码",

    303: "解析参数失败",
    304: "未找到对应数据",
}

LazyLoader_MSG_EN = {
    201: "Successfully updated the configuration",
    202: "Successfully deleted configuration",
    203: "Downloading sample code",

    303: "Failed to parse parameters",
    304: "No corresponding data found",
}

Empty_MSG = {
    201: "",
    202: "",
    203: "",
    204: "",
    205: "",
    206: "",

    301: "",
    302: "",
    303: "",
    304: "",
    305: "",
    306: "",
}

# token超时时间
EXPIRE_MINUTES = 24 * 60

# 静态配置信息
MSF_RPC_RESULT_CHANNEL = "MSF_RPC_RESULT_CHANNEL"
MSF_RPC_DATA_CHANNEL = "MSF_RPC_DATA_CHANNEL"
MSF_RPC_HEARTBEAT_CHANNEL = "MSF_RPC_HEARTBEAT_CHANNEL"
MSF_RPC_CONSOLE_PRINT = "MSF_RPC_CONSOLE_PRINT"
MSF_RPC_LOG_CHANNEL = "MSF_RPC_LOG_CHANNEL"
MSF_RPC_CONSOLE_CHANNEL = "MSF_RPC_CONSOLE_CHANNEL"
VIPER_SEND_SMS_CHANNEL = "VIPER_SEND_SMS_CHANNEL"
VIPER_POSTMODULE_AUTO_CHANNEL = "VIPER_POSTMODULE_AUTO_CHANNEL"

VIPER_RPC_UUID_JSON_DATA = "VIPER_RPC_UUID_JSON_DATA"

VIPER_PROXY_HTTP_SCAN_DATA = "VIPER_PROXY_HTTP_SCAN_DATA"

PAYLOAD_LOADER_STORE_PATH = "STATICFILES/STATIC/SHELLCODELOADER/"

# 静态文件目录
STATIC_STORE_PATH = "STATICFILES/STATIC/"

# meterpreter prompt
METERPRETER_PROMPT = "meterpreter > "
SHELL_PROMPT = "shell > "
MSFLOOT = "/root/.msf4/loot"

# timeout
RPC_FRAMEWORK_API_REQ = 15  # 框架类请求
RPC_JOB_API_REQ = 3  # 后台任务类请求
RPC_SESSION_OPER_SHORT_REQ = 15  # 涉及Session操作类请求
RPC_SESSION_OPER_LONG_REQ = 120  # 涉及Session操作类请求
RPC_RUN_MODULE_LONG = 120  # 涉及Session操作类请求

# lang
CN = "zh-CN"
EN = "en-US"

# viper config
VIPER_IP = "255.255.255.255"

MSF_MODULE_CALLBACK_WAIT_SENCOND = 30
