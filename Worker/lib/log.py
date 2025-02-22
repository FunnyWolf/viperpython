import logging.config

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
    },
    'formatters': {
        'standard': {
            'format': '[%(levelname)s][%(asctime).19s][%(pathname)s][%(lineno)d][%(threadName)s] : %(message)s '
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'formatter': 'standard',
            'filename': '/root/viper/Docker/log/worker.log',
        },
    },
    'loggers': {
        'worker': {
            'handlers': [
                'console',
                'file',
            ],
            'level': 'INFO',
            'propagate': True,
        },
    }
}
logging.config.dictConfig(LOGGING)

# 获取Django的logger
logger = logging.getLogger('worker')
