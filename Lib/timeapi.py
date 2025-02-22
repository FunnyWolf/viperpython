import time


class TimeAPI(object):
    def __init__(self):
        pass

    @staticmethod
    def str_to_timestamp(timestr, format="%Y-%m-%d %H:%M:%S"):
        """时间字符串转时间戳"""
        #
        #
        # '%Y-%m-%dT%H:%M:%S.%fZ'
        return int(time.mktime(time.strptime(timestr, format)))

    @staticmethod
    def timestamp_to_str(timestamp, format="%Y-%m-%d %H:%M:%S"):
        """将时间戳转换为字符串."""
        try:
            return time.strftime(format, time.localtime(timestamp))
        except Exception as _:
            return None

    # @staticmethod
    # def str_to_timestamp(timestr, format='%Y-%m-%dT%H:%M:%S.%fZ'):
    #     # 转换为datetime对象
    #     dt = datetime.strptime(timestr, format)
    #
    #     # 转换为时间戳
    #     timestamp = int(dt.timestamp())
    #     return timestamp
