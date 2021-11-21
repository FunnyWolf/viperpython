import json

from asgiref.sync import async_to_sync
from channels.generic.websocket import WebsocketConsumer
from django.http.request import QueryDict

from Lib.log import logger
from Lib.xcache import Xcache
from WebSocket.Handle.console import Console
from WebSocket.Handle.heartbeat import HeartBeat


class MsfConsoleView(WebsocketConsumer):
    message = {'status': 0, 'message': None}

    def connect(self):
        """
        打开 websocket 连接
        :return:
        """
        query_string = self.scope.get('query_string')
        connect_request_args = QueryDict(query_string=query_string, encoding='utf-8')

        token = connect_request_args.get('token')
        if Xcache.alive_token(token):
            result = Console.get_active_console()
            if result:
                self.accept()
                async_to_sync(self.channel_layer.group_add)("msfconsole", self.channel_name)
                return
            else:
                self.disconnect(True)
                return
        else:
            logger.warning("Websocket 鉴权失败")
            self.disconnect(True)

    def disconnect(self, close_code):
        try:
            async_to_sync(self.channel_layer.group_discard)("msfconsole", self.channel_name)
            Xcache.clean_msfconsoleinputcache()
        except Exception as E:
            logger.exception(E)
            pass

    def send_message(self, event):
        inputdata = event['message']
        self.send(inputdata)

    def receive(self, text_data=None, bytes_data=None):
        """接收前端用户输入"""
        message = json.loads(text_data)
        input_data = message.get("data")
        cmd = message.get("cmd")
        # \r \t \x7f
        # ctrl+c \x03
        # ctrl+z \x1a
        if cmd == "reset":
            Console.reset_active_console()
            Xcache.clean_msfconsoleinputcache()
            return

        cache_str = Xcache.get_msfconsoleinputcache()
        # 输入处理
        if input_data == "\r" or input_data == "\r\n":
            Xcache.add_to_msfconsole_history_cache(cache_str)
            Xcache.clean_msfconsoleinputcache()
            flag, result = Console.write(cache_str + "\n")
            if flag:
                self.send_input_feedback(f"\r\n")
            else:
                self.send_input_feedback("\r\nConnect Error >")
        elif input_data == "\x7f":  # 删除键
            return_str = Xcache.del_one_from_msfconsoleinputcache()
            self.send_input_feedback(return_str)
        elif input_data == "\t":  # tab键
            flag, result = Console.tabs(cache_str)
            if flag is not True:
                extra_str = "\r\nConnect Error >"
                self.send_input_feedback(extra_str)
                return
            tabs = result.get("tabs")
            if tabs == None or len(tabs) == 0:
                return
            elif len(tabs) == 1:
                extra_str = tabs[0][len(cache_str):]
                self.send_input_feedback(extra_str)
                Xcache.add_to_msfconsoleinputcache(extra_str)
            else:
                tmp = self.deal_tabs_options(cache_str, tabs)
                if tmp is None or tmp == cache_str:
                    extra_str = "\r\n"
                    for one in tabs:
                        extra_str = extra_str + one + "\r\n"
                    prompt = result.get("prompt")
                    extra_str = extra_str + prompt + cache_str
                    self.send_input_feedback(extra_str)
                else:
                    extra_str = tmp[len(cache_str):]
                    self.send_input_feedback(extra_str)
                    Xcache.add_to_msfconsoleinputcache(extra_str)
        elif input_data == "\x1b[A":  # 上键
            clear_cmd = Xcache.clear_oneline_from_msfconsoleinputcache()
            self.send_input_feedback(clear_cmd)
            last = Xcache.get_last_from_msfconsole_history_cache()
            if last is None:
                pass
            else:
                Xcache.add_to_msfconsoleinputcache(last)
                self.send_input_feedback(last)
        elif input_data == "\x1b[B":  # 上键
            clear_cmd = Xcache.clear_oneline_from_msfconsoleinputcache()
            self.send_input_feedback(clear_cmd)
            last = Xcache.get_next_from_msfconsole_history_cache()
            if last is None:
                pass
            else:
                Xcache.add_to_msfconsoleinputcache(last)
                self.send_input_feedback(last)
        elif input_data == '\x03':  # ctrl+c
            Console.session_kill()
            Xcache.clean_msfconsoleinputcache()
            flag, result = Console.write("\n")
            if flag:
                self.send_input_feedback(f"\r\n")
            else:
                self.send_input_feedback("\r\nConnect Error >")
        elif input_data == '\x1a':  # ctrl+z
            Console.session_detach()
            Xcache.clean_msfconsoleinputcache()
            flag, result = Console.write("\n")
            if flag:
                self.send_input_feedback(f"\r\n")
            else:
                self.send_input_feedback("\r\nConnect Error >")
        elif isinstance(input_data, str):
            Xcache.add_to_msfconsoleinputcache(input_data)
            self.send_input_feedback(input_data)
        else:
            pass

    def send_input_feedback(self, data=''):
        message = {}
        message['status'] = 0
        message['data'] = data
        message = json.dumps(message)
        async_to_sync(self.channel_layer.group_send)(
            "msfconsole",
            {
                'type': 'send_message',
                'message': message
            }
        )

    def deal_tabs_options(self, input, tabs):
        if len(tabs) == 0:
            return None
        if len(tabs) == 1:
            return tabs[0]
        newlength = len(input) + 1
        return_str = input
        while True:
            if newlength >= len(tabs[0]):
                return tabs[0][0:newlength]
            tmp_str = tabs[0][0:newlength]
            for one_tab in tabs:
                if tmp_str not in one_tab:
                    return return_str
            return_str = tmp_str
            newlength = newlength + 1


class HeartBeatView(WebsocketConsumer):
    Unauth = 3000

    def connect(self):
        """
        打开 websocket 连接
        :return:
        """
        query_string = self.scope.get('query_string')
        connect_request_args = QueryDict(query_string=query_string, encoding='utf-8')

        token = connect_request_args.get('token')

        if Xcache.alive_token(token):
            result = HeartBeat.first_heartbeat_result()
            self.accept()
            async_to_sync(self.channel_layer.group_add)("heartbeat", self.channel_name)
            self.send(json.dumps(result))
            return
        else:
            logger.warning("Websocket 鉴权失败")

    def disconnect(self, close_code=0):
        try:
            async_to_sync(self.channel_layer.group_discard)("heartbeat", self.channel_name)
        except:
            pass
        super().close(code=close_code)

    def send_message(self, event):
        message = event['message']
        data = ""
        try:
            data: str = json.dumps(message, skipkeys=True)
        except Exception as E:
            logger.exception(E)
            logger.warning(message)

        self.send(data)
