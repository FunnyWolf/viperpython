from django.apps import AppConfig


class InitConfig(AppConfig):
    name = 'Init'

    def ready(self):
        from Lib.montior import MainMonitor
        MainMonitor().start()
