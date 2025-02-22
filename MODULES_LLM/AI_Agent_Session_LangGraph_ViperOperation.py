# -*- coding: utf-8 -*-
if __name__ == '__main__':
    import os

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Viper.settings")
    import django

    django.setup()

from typing import Literal

from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langgraph.graph import END, StateGraph, MessagesState
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode

from Lib.ModuleAPI import *
from Lib.configs import USER_INPUT

AGENT_NODE = "AGENT_NODE"
TOOL_NODE = "TOOL_NODE"
CLEAN_NODE = "CLEAN_NODE"


class PostModule(LLMPythonModule):
    NAME_ZH = "平台操作智能体"
    DESC_ZH = ("使用自然语言对平台及Session进行操作.\n"
               "例如: 'Session 1 有多少个用户在登录?' 'Session 1 所在主机和哪些内网IP有连接' 'viper平台认证token是什么?'")

    NAME_EN = "Viper Operation Agent"
    DESC_EN = ("Use natural language to do operation on platform and session.\n "
               "For example: 'How many users are logged on now?' 'What are the hosts and which internal IPs are connected'")
    TAGS = ["LangChain", "LangGraph", "Chat History"]
    MODULETYPE = TAG2TYPE.AI_Multi_Agent
    AUTHOR = ["Viper"]
    README = ["https://www.yuque.com/vipersec/module/xa5wp4culfcr9rbw"]
    REFERENCES = [""]
    OPTIONS = []

    def __init__(self, custom_param):
        super().__init__(custom_param)
        self.init()

    def init(self):
        openai_api = OpenAIAPI()
        self.llm = openai_api.get_model()

        tools = [
            llmfunc.function_call_debug,
            llmfunc.get_session_host_info,
            llmfunc.list_session,
            llmfunc.get_session_info,
            llmfunc.list_handler,
            llmfunc.list_host,
            llmfunc.list_route,
            llmfunc.query_route_by_ipaddress,
            llmfunc.session_meterpreter_run
        ]
        tool_node = ToolNode(tools, name=TOOL_NODE)

        def route_after_agent(state: MessagesState) -> Literal[TOOL_NODE, CLEAN_NODE]:
            messages = state['messages']
            last_message = messages[-1]
            if last_message.tool_calls:
                return TOOL_NODE
            return CLEAN_NODE

        def agent_node(state: MessagesState):
            agent_prompt = llmapi.AgentPrompt()
            agent_prompt.role = "高级网络安全红队专家"
            agent_prompt.goal = "利用提供的工具和丰富的网络安全经验完成任务"
            agent_prompt.backstory = []
            agent_prompt.require_input = ["用户需要达成的目标和用户必须提供的信息"]
            agent_prompt.task_desc = ["根据用户的需求制定计划并通过调用平台工具完成任务"]
            agent_prompt.task_requirement = []
            agent_prompt.expected_output = "完整的计划及计划执行之后的结果"
            agent_prompt.notes = []
            chat_template = ChatPromptTemplate.from_messages(
                [
                    agent_prompt.system_prompt(),
                    MessagesPlaceholder(variable_name='messages', optional=True),
                ]
            )

            messages = chat_template.format_prompt(messages=state['messages']).to_messages()
            llm_with_tools = self.llm.bind_tools(tools)
            response = llm_with_tools.invoke(messages)
            # We return a list, because this will get added to the existing list
            return {"messages": [response]}

        workflow = StateGraph(MessagesState)

        workflow.add_node(AGENT_NODE, agent_node)
        workflow.add_node(TOOL_NODE, tool_node)
        workflow.add_node(CLEAN_NODE, llmapi.clean_node)

        workflow.set_entry_point(AGENT_NODE)
        workflow.add_conditional_edges(AGENT_NODE, route_after_agent)
        workflow.add_edge(TOOL_NODE, AGENT_NODE)
        workflow.add_edge(CLEAN_NODE, END)

        self.graph: CompiledStateGraph = workflow.compile(checkpointer=self.get_checkpointer())
        return True

    def check(self):
        """执行前的检查函数"""
        return True, None

    def run(self):
        self.run_graph()


if __name__ == '__main__':
    # user_input = "当前已经控制的主机桌面上有哪些有价值的文件"
    # user_input = "生成一个随机字符串,magic num 666"
    user_input = "平台当前session列表"
    post_module_instance = PostModule(custom_param={USER_INPUT: user_input})
    post_module_instance.run_graph_debug()
    # post_module_instance.export_graph_png()
