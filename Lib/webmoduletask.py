class WebModuleTaskStatus(object):
    running = "running"
    waiting = "waiting"


class WebModuleTask(object):
    def __init__(self):
        self.broker = None
        self.task_uuid = None
        self.module = None
        self.time = None
        self.module_config = None
        self.status = WebModuleTaskStatus.waiting
