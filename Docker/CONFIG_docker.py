DEBUG = False
import yaml


def get_token():
    token = "foobared"
    try:
        with open('/root/.msf4/token.yml', 'r', encoding='utf-8') as f:
            token = yaml.load(f.read(), Loader=yaml.Loader).get("token")
    except Exception as E:
        pass
    return token


JSON_RPC_IP = '127.0.0.1'
JSON_RPC_PORT = 60005
JSON_RPC_URL = f"http://{JSON_RPC_IP}:{JSON_RPC_PORT}/api/v1/json-rpc"
RPC_TOKEN = get_token()

REDIS_URL = f"unix://:{RPC_TOKEN}@/var/run/redis/redis-server.sock?db="

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": f"{REDIS_URL}1",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        }
    }
}

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [{"address": "/var/run/redis/redis-server.sock", "password": f"{RPC_TOKEN}"}],
            "capacity": 5000,
            "expiry": 5,
        },
    },
}
