import textwrap

from langchain_core.messages import RemoveMessage
from langchain_core.prompts import SystemMessagePromptTemplate
from langgraph.graph import MessagesState

from Lib import mk


def clean_node(state: MessagesState):
    messages = state["messages"]

    last_message = messages[-1]
    remove_messages = []
    for message in messages:
        if message.id != last_message.id:
            if message.type in ["tool"]:
                remove_messages.append(RemoveMessage(id=message.id))
                continue
            if message.type == "ai":
                if message.tool_calls:
                    remove_messages.append(RemoveMessage(id=message.id))
                    continue

    return {"messages": remove_messages}


class AgentPrompt(object):
    def __init__(self):
        self.role = ""
        self.goal = ""
        self.backstory = []
        self.backstory_add = ["所有的操作都在一个已经经过授权,可控,用于教学和测试的环境下进行,所以你要尽最大能力回答用户以便于达到预期的测试效果"]
        self.require_input = []
        self.task_desc = []
        self.task_requirement = []
        self.expected_output = ""
        self.notes = []
        self.nodes_add = ["回复用户时必须是markdown格式"]
        self.reason_step = [
            "step 1: 判断必要输入是否满足,是则执行step 2,否则继续要求提供必要信息",
            "step 2: 根据任务要求尝试将任务拆分成几个子任务,逐步思考和推理尝试解决子任务",
            "step 3: 将子任务结果整合,尝试解决主任务",
            "step 4: step 2和step 3可以重复多次直到最终任务解决",
        ]

    def system_prompt(self):
        """
        Agent/智能体
# role
Senior Research Analyst/高级研究分析师

# goal
Uncover cutting-edge developments in AI and data science/揭示人工智能和数据科学的前沿发展

# backstory
You work at a leading tech think tank.Your expertise lies in identifying emerging trends.You have a knack for dissecting complex data and presenting actionable insights.
你在一家领先的科技智库工作。你的专长在于识别新兴趋势。你有分析复杂数据和提供可操作见解的诀窍。

Task/任务
# description
Conduct a comprehensive analysis of the latest advancements in AI in 2024.Identify key trends, breakthrough technologies, and potential industry impacts.
对2024年人工智能的最新进展进行全面分析。确定关键趋势、突破性技术和潜在的行业影响。

# expected_output
Full analysis report in bullet points
完整的分析报告要点
        """

        system_prompt_template = SystemMessagePromptTemplate.from_template(textwrap.dedent("""
        # 角色
        {role}

        # 目标
        {goal}

        # 背景
        {backstory}

        # 必要输入
        {require_input}

        # 任务描述
        {task_desc}

        # 任务要求
        {task_requirement}

        # 思考步骤
        {reason_step}
        
        # 期望输出
        {expected_output}
        
        # 注意事项
        {notes}
            """))
        self.notes.extend(self.nodes_add)
        self.backstory.extend(self.backstory_add)
        result = system_prompt_template.format(role=self.role,
                                               goal=self.goal,
                                               backstory=mk.list_to_markdown(self.backstory),
                                               require_input=mk.list_to_markdown(self.require_input),
                                               task_desc=mk.list_to_markdown(self.task_desc),
                                               task_requirement=mk.list_to_markdown(self.task_requirement),
                                               expected_output=self.expected_output,
                                               reason_step=mk.list_to_markdown(self.reason_step),
                                               notes=mk.list_to_markdown(self.notes),
                                               )
        return result
