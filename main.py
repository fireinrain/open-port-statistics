import datetime
import json
import os
import random
import shutil
import subprocess
import sys
import uuid
from collections import defaultdict
from matplotlib import pyplot as plt
import requests
import redis
import time
from log import logger
import asn

redis_host = os.getenv("REDIS_HOST", "127.0.0.1")
redis_port = int(os.getenv("REDIS_PORT", 6379))
redis_pass = os.getenv("REDIS_PASS", "mypass")

pool = redis.ConnectionPool(
    host=redis_host,
    port=redis_port,
    db=0, password=redis_pass,
    socket_connect_timeout=60 * 60 * 6,
    socket_timeout=60 * 60 * 6,
    max_connections=4
)
# 适配的redis版本
# 初始化 Redis 连接
r = redis.Redis(connection_pool=pool,
                ssl=False)


def acquire_lock_with_timeout(redis_client, lock_name, acquire_timeout=60 * 60, lock_timeout=60 * 60):
    identifier = str(uuid.uuid4())
    end = time.time() + acquire_timeout
    while time.time() < end:
        if redis_client.set(lock_name, identifier, nx=True, ex=lock_timeout):
            return identifier
        time.sleep(0.001)
    return False


def release_lock(redis_client, lock_name, identifier):
    while True:
        try:
            with redis_client.pipeline() as pipe:
                pipe.watch(lock_name)
                lock_value = redis_client.get(lock_name)
                if lock_value and lock_value.decode('utf-8') == identifier:
                    pipe.multi()
                    pipe.delete(lock_name)
                    pipe.execute()
                    return True
                pipe.unwatch()
                break
        except redis.WatchError:
            continue
    return False


# 获取所有 CIDR 列表
def get_cidr_ips(asn):
    # 确保 asn 目录存在
    asn_dir = "asn"
    os.makedirs(asn_dir, exist_ok=True)

    file_path = os.path.join(asn_dir, f"{asn}")

    # 检查是否存在对应的 ASN 文件
    if os.path.exists(file_path):
        # 如果文件存在，读取文件内容
        with open(file_path, 'r') as file:
            cidrs = json.load(file)
        print(f"CIDR data for ASN {asn} loaded from file.")
    else:
        # 如果文件不存在，请求 API 数据
        url = f'https://api.bgpview.io/asn/{asn}/prefixes'
        headers = {
            "User-Agent": "curl/7.68.0"
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        cidrs = [prefix['prefix'] for prefix in data['data']['ipv4_prefixes']]

        # 将数据写入文件
        with open(file_path, 'w') as file:
            json.dump(cidrs, file)
        print(f"CIDR data for ASN {asn} fetched from API and saved to file.")

    return cidrs


# 将 CIDR 列表存入 Redis
def store_cidrs_in_redis(asn, batch_ip_size):
    cidrs = get_cidr_ips(asn)

    def ip_count(cidr):
        ip, mask = cidr.split('/')
        mask = int(mask)
        return 2 ** (32 - mask) if mask < 32 else 1

    total_ips = sum(ip_count(cidr) for cidr in cidrs)

    if total_ips <= batch_ip_size:
        r.rpush(f"cidr_batches:{asn}", json.dumps(cidrs))
    else:
        batches = []
        current_batch = []
        current_batch_ip_count = 0
        for cidr in cidrs:
            cidr_ip_count = ip_count(cidr)
            if current_batch_ip_count + cidr_ip_count > batch_ip_size and current_batch:
                batches.append(current_batch)
                current_batch = []
                current_batch_ip_count = 0
            current_batch.append(cidr)
            current_batch_ip_count += cidr_ip_count

        if current_batch:
            batches.append(current_batch)

        # 如果批次数量大于 10，均匀分成十份
        if len(batches) > 10:
            total_cidrs = [cidr for batch in batches for cidr in batch]
            chunk_size = len(total_cidrs) // 10
            batches = [total_cidrs[i * chunk_size: (i + 1) * chunk_size] for i in range(10)]
            if len(total_cidrs) % 10 != 0:
                for i in range(len(total_cidrs) % 10):
                    batches[i].append(total_cidrs[-(i + 1)])

        for batch in batches:
            r.rpush(f"cidr_batches:{asn}", json.dumps(batch))


def ip_count(cidr):
    ip, mask = cidr.split('/')
    mask = int(mask)
    return 2 ** (32 - mask) if mask < 32 else 1


def split_large_batches(batches, batch_ip_size):
    new_batches = []
    for batch in batches:
        if len(new_batches) >= 10:
            new_batches.append(batch)
            continue
        current_batch = []
        current_batch_ip_count = 0
        for cidr in batch:
            cidr_ip_count = ip_count(cidr)
            if current_batch_ip_count + cidr_ip_count > batch_ip_size and current_batch:
                new_batches.append(current_batch)
                current_batch = []
                current_batch_ip_count = 0
                if len(new_batches) >= 10:
                    break
            current_batch.append(cidr)
            current_batch_ip_count += cidr_ip_count
        if current_batch:
            new_batches.append(current_batch)
        if len(new_batches) >= 10:
            break
    return new_batches


# 获取 CIDR 批次
def get_cidr_batch(asn):
    cidr_batch = r.lpop(f"cidr_batches:{asn}")
    if cidr_batch:
        return json.loads(cidr_batch)
    return []


# 使用 Masscan 扫描所有 IP 的端口
def scan_ip_range(cidr, output_file, scan_ports="443"):
    cmd = ["masscan", cidr, f"-p{scan_ports}", "--rate=20000", "--wait=3", "-oL", output_file]
    print(f"Executing command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("Scan completed successfully.")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing masscan: {e}")
        print(f"Exit status: {e.returncode}")
        print(f"Standard output: {e.stdout}")
        print(f"Standard error: {e.stderr}")


# 解析 Masscan 输出并统计端口
def parse_masscan_output(file_path):
    port_counts = defaultdict(int)
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('open'):
                parts = line.split()
                if len(parts) >= 3:
                    port = int(parts[2])
                    port_counts[port] += 1
    return port_counts


# 将端口统计结果存储到 Redis
def store_port_counts_in_redis(asn, port_counts):
    lock_name = f"lock:port_counts:{asn}"
    identifier = acquire_lock_with_timeout(r, lock_name)

    if identifier:
        try:
            for port, count in port_counts.items():
                r.hincrby(f"port_counts:{asn}", port, count)
        finally:
            release_lock(r, lock_name, identifier)
    else:
        print("Failed to acquire lock for updating port_counts")


# def store_port_counts_in_redis(asn, port_counts):
#     for port, count in port_counts.items():
#         r.hincrby(f"port_counts:{asn}", port, count)


# 绘制条形图
def plot_port_statistics(asn, scan_ports):
    result_dir = os.path.join('ports_results', asn)
    os.makedirs(result_dir, exist_ok=True)

    # 从 Redis 获取所有端口统计结果
    all_port_counts = defaultdict(int)
    port_counts = r.hgetall(f"port_counts:{asn}")
    for port, count in port_counts.items():
        all_port_counts[int(port)] = int(count)

    fig, ax = plt.subplots(figsize=(15, 8))

    if ',' in scan_ports:
        ports = sorted(all_port_counts.keys())
        counts = [all_port_counts[p] for p in ports]

        bars = ax.bar(ports, counts)

        max_count = max(counts)
        norm = plt.Normalize(0, max_count)
        for bar, count in zip(bars, counts):
            color = plt.cm.viridis(norm(count))
            bar.set_color(color)

        ax.set_xlabel('Port')
        ax.set_ylabel('Number of Open Ports')
        ax.set_title(f'Distribution of Open Ports (ASN {asn}, Ports: {scan_ports})')

        ax.set_xticks(ports)
        ax.set_xticklabels(ports, rotation=90)

        text_str = '\n'.join([f'Port {port}: {count}' for port, count in zip(ports, counts)])
    else:
        port_ranges = scan_ports.split('-')
        start_port = int(port_ranges[0])
        end_port = int(port_ranges[1])
        num_groups = min(66, (end_port - start_port) // 1000 + 1)
        step = (end_port - start_port + 1) // num_groups
        groups = list(range(num_groups))
        counts = [0] * num_groups
        for port, count in all_port_counts.items():
            group = (port - start_port) // step
            if 0 <= group < num_groups:
                counts[group] += count

        bars = ax.bar(groups, counts)

        max_count = max(counts)
        norm = plt.Normalize(0, max_count)
        for bar, count in zip(bars, counts):
            color = plt.cm.viridis(norm(count))
            bar.set_color(color)

        ax.set_xlabel('Port Range (in thousands)')
        ax.set_ylabel('Number of Open Ports')
        ax.set_title(f'Distribution of Open Ports (ASN {asn}, Ports: {scan_ports})')

        ax.set_xticks(range(0, num_groups, max(num_groups // 10, 1)))
        ax.set_xticklabels([f'{i * step}k-{(i + 1) * step}k' for i in range(0, num_groups, max(num_groups // 10, 1))])

        text_str = '\n'.join(
            [f'Group {group * step}-{(group + 1) * step}k: {count}' for group, count in zip(groups, counts)])

    sm = plt.cm.ScalarMappable(cmap='viridis', norm=norm)
    sm.set_array([])
    cbar = plt.colorbar(sm, ax=ax, label='Relative Frequency')

    plt.tight_layout(rect=[0.15, 0, 1, 1])
    plt.figtext(0.02, 0.5, text_str, ha="left", va="center", fontsize=10,
                bbox={"facecolor": "white", "alpha": 0.5, "pad": 5})

    save_path = os.path.join(result_dir, f'port_distribution_asn{asn}_{scan_ports}.png')
    if os.path.exists(save_path):
        os.remove(save_path)
    plt.savefig(save_path)
    # plt.show()


def scan_and_store_results(asn, scan_ports):
    os.makedirs("masscan_results", exist_ok=True)
    while True:
        batch = get_cidr_batch(asn)
        if not batch:
            break
        cidrs = " ".join(batch)
        output_file = f"masscan_results/{batch[0].replace('/', '-')}_temp.txt"
        scan_ip_range(cidrs, output_file, scan_ports)
        port_counts = parse_masscan_output(output_file)
        store_port_counts_in_redis(asn, port_counts)
        time.sleep(5)  # 等待一会儿再获取下一个批次

    print(f"当前节点任务已经完成: {datetime.datetime.now()}")
    clear_directory("masscan_results")


def clear_directory(folder_path):
    # 确保文件夹存在
    if os.path.exists(folder_path):
        # 遍历文件夹中的所有内容
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            try:
                # 如果是文件夹，则递归删除
                if os.path.isdir(file_path):
                    shutil.rmtree(file_path)
                # 如果是文件，则直接删除
                else:
                    os.remove(file_path)
            except Exception as e:
                print(f'Error: {e}')


def find_files(start_dir, prefix):
    matching_files = []
    for root, dirs, files in os.walk(start_dir):
        for file in files:
            if file.startswith(prefix):
                abs_path = os.path.join(root, file)
                matching_files.append(abs_path)
            print(file)
    return matching_files


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


def clean_duplicate_redis_data(asn: str):
    clean_key = f"clean_lock:{asn}"
    initialized_key = f"task_initialized:{asn}"
    exists = r.exists(initialized_key)
    if exists:
        return
        # 使用 Redis 的原子操作 set 配合 NX 选项
    if r.set(clean_key, "1", nx=True):
        try:
            keys_to_delete = r.keys(f'*{asn}*')

            # 删除这些键
            if keys_to_delete:
                r.delete(*keys_to_delete)
        except Exception as e:
            # 如果初始化过程中出现错误，删除标记键以允许重试
            r.delete(clean_key)
    else:
        print(f"Redis数据已被其他服务器清理 {asn}")


def initialize_task(asn, batch_ip_size):
    initialized_key = f"task_initialized:{asn}"

    # 使用 Redis 的原子操作 set 配合 NX 选项
    if r.set(initialized_key, "1", nx=True):
        try:
            store_cidrs_in_redis(asn, batch_ip_size)
            print(f"Task initialized for ASN {asn}")
        except Exception as e:
            # 如果初始化过程中出现错误，删除标记键以允许重试
            r.delete(initialized_key)
            print(f"Error initializing task for ASN {asn}: {e}")
            raise
    else:
        print(f"Task already initialized for ASN {asn}")


def mark_task_completed(asn, num_instances):
    lock_name = f"completion_lock:{asn}"
    identifier = acquire_lock_with_timeout(r, lock_name)
    if identifier:
        try:
            completed_key = f"completed_instances:{asn}"
            completed_instances = int(r.get(completed_key) or 0)
            if completed_instances < num_instances:
                r.incr(completed_key)
                logger.info("任务已完成...")
            else:
                logger.info("所有实例已经完成任务，不需要再增加计数")
        finally:
            release_lock(r, lock_name, identifier)


def is_task_completed(asn, num_instances):
    lock_name = f"lock:task_check:{asn}"
    identifier = acquire_lock_with_timeout(r, lock_name, acquire_timeout=10, lock_timeout=10)

    if not identifier:
        logger.warning(f"Failed to acquire lock for task check for ASN {asn}")
        return False

    try:
        completed_key = f"completed_instances:{asn}"
        completed_instances = int(r.get(completed_key) or 0)
        logger.info(f"Task completed: {completed_instances} instances")
        return completed_instances >= num_instances
    finally:
        release_lock(r, lock_name, identifier)


def run_task(asn_number: str):
    asn = asn_number
    clean_duplicate_redis_data(asn)
    scan_ports = '80,443,2052,2053,2082,2083,2086,2087,2095,2096,8080,8443,8880'
    batch_ip_size = 100000  # Example batch size

    # 初始化任务，只需执行一次
    initialize_task(asn, batch_ip_size)

    # 等待十秒
    time.sleep(random.randint(1, 10))

    scan_and_store_results(asn, scan_ports)

    # 检查是否所有实例都完成任务
    num_instances = 10  # 假设有十台机器
    # 标记任务完成
    mark_task_completed(asn, num_instances)

    while True:
        if is_task_completed(asn, num_instances):
            # 如果是最后一台完成的机器，则生成图表和刷新 Markdown
            if r.incr(f"last_instance:{asn}") == 1:
                plot_port_statistics(asn, scan_ports)
                refresh_markdown("ports_results")
            break
        logger.info(f"等待其他节点完成任务(睡眠10s)...")
        time.sleep(10)


def main():
    asn = "906"
    argv_ = sys.argv
    if len(argv_) <= 1:
        run_task(asn)
        return
    else:
        if argv_[1] == "clean":
            keys_to_delete = r.keys(f'*{asn}*')
            # 删除这些键
            if keys_to_delete:
                r.delete(*keys_to_delete)
            print(f"清理上次数据残留成功...")


if __name__ == "__main__":
    main()
