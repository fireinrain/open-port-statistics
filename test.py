import os

import redis

import asn
from main import find_files


def refresh_markdown(results_dir: str):
    start_directory = results_dir
    file_prefix = 'port_distribution'
    found_files = find_files(start_directory, file_prefix)
    print(f"发现统计图片: {found_files}")
    markdown = '''
# open-ports-distributed
scan asn and detect the open port and make a statics with graph
## Open Ports Result    
'''
    markdown += '\n'

    images_nodes = [
        f'## {asn.ASN_Map.get(i.split("/")[-1].split("_")[2].replace("asn", ""), "UnknownASN")}\n### {i.split("/")[-1].replace("port_distribution_", "")}\n![{i.split("/")[-1]}]({i})'
        for i in
        found_files]
    images_nodes_str = "\n".join(images_nodes)

    markdown += images_nodes_str
    with open('README.md', 'w') as f:
        f.write(markdown)
        f.flush()


def test_env_injection():
    redis_host = os.getenv("REDIS_HOST", "127.0.0.1")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    redis_pass = os.getenv("REDIS_PASS", "mypass")

    print("Environment injection")
    print(redis_host)
    print(redis_port)
    print(redis_pass)

    # 初始化 Redis 连接
    r = redis.Redis(
        host=redis_host,
        port=redis_port,
        password=redis_pass,
        db=0,
        ssl=False
    )
    ping = r.ping()
    print(f"Resp from redis: {ping}")


if __name__ == '__main__':
    # refresh_markdown("ports_results")
    test_env_injection()
