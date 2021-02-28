JSON_RPC_IP = '127.0.0.1'
JSON_RPC_PORT = 60005
JSON_RPC_URL = "http://{}:{}/api/v1/json-rpc".format(JSON_RPC_IP, JSON_RPC_PORT)
RPC_TOKEN = 'for_msf_token_as_password'
MSFDIR = "/root/.msf4/"
DEBUG = False

REDIS_URL = "unix://:foobared@/var/run/redis/redis-server.sock?db="

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
            "hosts": [{"address": "/var/run/redis/redis-server.sock", "password": "foobared"}],
            "capacity": 5000,
            "expiry": 5,
        },
    },
}
MSFLOOTTRUE = "/root/.msf4/loot"  # 为了调试
