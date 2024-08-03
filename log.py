# 配置日志记录
import logging

logging.basicConfig(level=logging.DEBUG,  # 设置日志级别为DEBUG
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # 设置日志格式
                    handlers=[
                        logging.FileHandler('app.log'),  # 日志记录到文件
                        logging.StreamHandler()  # 日志记录到控制台
                    ])

# 创建一个日志记录器
logger = logging.getLogger(__name__)
