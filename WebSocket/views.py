import json
from threading import Thread

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
        async_to_sync(self.channel_layer.group_add)("msfconsole", self.channel_name)
        self.accept()
        query_string = self.scope.get('query_string')
        ssh_args = QueryDict(query_string=query_string, encoding='utf-8')

        token = ssh_args.get('token')
        if Xcache.alive_token(token):
            result = Console.get_active_console()
            if result:
                return
            else:
                self.disconnect(True)
                return
        else:
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
            Thread(target=self.send_msfrpc_read).start()
            return

        cache_str = Xcache.get_msfconsoleinputcache()
        # 输入处理
        if input_data == "\r" or input_data == "\r\n":
            Xcache.add_to_msfconsole_history_cache(cache_str)
            if cache_str.lower() == "exit -f":
                cache_str = "exit"

            Console.write(cache_str + "\r\n")
            Xcache.clean_msfconsoleinputcache()
            self.send_input_feedback("\r\n")
            Thread(target=self.send_msfrpc_read).start()
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
            Console.write("\r\n")
            self.send_input_feedback("\r\n")
            Thread(target=self.send_msfrpc_read).start()
        elif input_data == '\x1a':  # ctrl+z
            Console.session_detach()
            Xcache.clean_msfconsoleinputcache()
            Console.write("\r\n")
            self.send_input_feedback("\r\n")
            Thread(target=self.send_msfrpc_read).start()
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
        # self.send(message)
        async_to_sync(self.channel_layer.group_send)(
            "msfconsole",
            {
                'type': 'send_message',
                'message': message
            }
        )

    def send_msfrpc_read(self):
        while True:
            flag, result = Console.read()
            if flag is not True:
                self.send_input_feedback("\r\nConnect Error >")
                return
            data = result.get("data").replace("\n", "\r\n")
            if len(data) == 0:
                self.send_input_feedback(result.get("prompt"))
                return
            else:
                self.send_input_feedback(result.get("data").replace("\n", "\r\n"))

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
    def connect(self):
        """
        打开 websocket 连接
        :return:
        """
        async_to_sync(self.channel_layer.group_add)("heartbeat", self.channel_name)
        self.accept()

        query_string = self.scope.get('query_string')
        ssh_args = QueryDict(query_string=query_string, encoding='utf-8')

        token = ssh_args.get('token')
        if Xcache.alive_token(token):
            result = HeartBeat.first_heartbeat_result()
            self.send(json.dumps(result))
            return
        else:
            self.disconnect()

    def disconnect(self, close_code=0):
        try:
            async_to_sync(self.channel_layer.group_discard)("heartbeat", self.channel_name)
        except:
            pass

    def send_message(self, event):
        message = event['message']
        self.send(json.dumps(message))
