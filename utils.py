import os

import redis


def clean_redis_db():
    redis_host = os.getenv("REDIS_HOST", "127.0.0.1")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    redis_pass = os.getenv("REDIS_PASS", "mypass")

    # 初始化 Redis 连接
    r = redis.Redis(
        host=redis_host,
        port=redis_port,
        password=redis_pass,
        db=0,
        ssl=False
    )
    r.flushall()
    # info = r.info()
    # print(info)
    print(f"清空redis完成")


if __name__ == '__main__':
    clean_redis_db()
