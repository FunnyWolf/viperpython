from gevent import monkey

# monkey.patch_all(thread=False, select=False, httplib=True)
monkey.patch_all(thread=False)
import json

from lib.log import logger
from lib.redisclient import RedisClient

from wafw00f.wafcheck import WafCheck
import sys


class RPCServer(object):
    """Executes function calls received from a Redis queue."""

    def __init__(self):
        self.redis_server = RedisClient.get_result_connection()

    def run(self, request_queue, response_queue):
        logger.info(f"Run Start: {request_queue}")
        message_queue, message = self.redis_server.blpop(request_queue)
        try:
            rpc_request = json.loads(message.decode())
            kwargs = rpc_request.get('kwargs')
        except Exception as E:
            logger.exception(E)
            logger.warning(message)
            return

        # scanner
        urls = kwargs.get("urls")
        wafcheck = WafCheck()
        wafcheck.scan_gevent(urls)

        rpc_response = wafcheck.results
        self.redis_server.rpush(response_queue, json.dumps(rpc_response))
        logger.info(f"RPC rpush response {response_queue}")


if __name__ == '__main__':
    if len(sys.argv) <= 2:
        exit()
    else:
        request_queue = sys.argv[1]
        response_queue = sys.argv[2]
        rpc_server = RPCServer()
        rpc_server.run(request_queue=request_queue, response_queue=response_queue)
