from Lib.configs import WAFCHECK
from Lib.rpccall import RpcCall


class Worker(object):
    def __init__(self):
        pass

    @staticmethod
    def ping_wafcheck():
        rpc_response = RpcCall.rpc_call(worker=WAFCHECK, timeout=10, urls=[])
        if rpc_response is not None:
            return True
        else:
            return False
