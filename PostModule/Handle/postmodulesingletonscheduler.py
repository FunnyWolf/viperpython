from apscheduler.schedulers.background import BackgroundScheduler

# 独立文件,防止import循环
# 用于执行post模块的定时任务单例
postModuleSingletonScheduler = BackgroundScheduler(timezone='Asia/Shanghai')
