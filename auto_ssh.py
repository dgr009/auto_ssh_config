import socket
import ipaddress
import paramiko
from paramiko.config import SSHConfig
import argparse
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import os
from datetime import datetime

DEFAULT_KEY_DIR = os.getenv("SSH_KEY_DIR", "~/aws-key")  # 환경 변수에서 읽기, 기본값 "~/key"

# 기존에 등록된 호스트 IP를 가져오는 함수
def get_existing_hosts():
    existing_ips = set()
    config_path = os.path.expanduser("~/.ssh/config")
    try:
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                for line in f:
                    if "Hostname" in line:
                        ip = line.strip().split()[-1]
                        existing_ips.add(ip)
    except IOError as e:
        print(f"~/.ssh/config 파일을 읽는 중 오류 발생: {e}")
    return existing_ips

# 포트가 열려 있는지 확인하는 함수
def is_port_open(ip, port, timeout=0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((str(ip), port))
    sock.close()
    return result == 0

# IP 대역 스캔 함수
def scan_ip_range(ip_range, port, exclude_ips):
    open_ips = []
    ips = [ip for ip in ip_range.hosts() if str(ip) not in exclude_ips]
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(is_port_open, ip, port): ip for ip in ips}
        for future in tqdm(futures, total=len(futures), desc="IP 스캔 진행 중"):
            if future.result():
                open_ips.append(futures[future])
    return open_ips

# 새 호스트를 .ssh/config에 추가하는 함수
def add_new_host(ip,port):
    print(f"\nIP {ip}를 등록하시겠습니까?")
    choice = input("선택 (1: 등록, 0: 등록 안 함, 기본값 0): ") or "0"
    if choice != "1":
        print(f"{ip} 등록을 건너뜁니다.")
        return
    
    host = input(f"{ip}의 호스트 이름을 입력하세요 (예: vm01): ")
    user_options = ["ubuntu", "rocky", "ec2-user", "centos", "root", "직접 입력"]
    print("사용자를 선택하세요 (기본값 1):")
    for i, opt in enumerate(user_options, 1):
        print(f"{i}. {opt}")
    user_choice = input("선택 (1-6): ") or "1"
    try:
        user_idx = int(user_choice) - 1
        if 0 <= user_idx < len(user_options):
            user = user_options[user_idx] if user_idx != 5 else input("사용자 이름 입력: ")
        else:
            print("잘못된 선택입니다. 기본값 'ubuntu'를 사용합니다.")
            user = "ubuntu"
    except ValueError:
        print("숫자를 입력해야 합니다. 기본값 'ubuntu'를 사용합니다.")
        user = "ubuntu"
    key_dir = os.path.expanduser(DEFAULT_KEY_DIR)
    key_files = [f for f in os.listdir(key_dir) if f.endswith((".pem", ".pub", ".key"))]
    print("IdentityFile을 선택하세요:")
    for i, key in enumerate(key_files, 1):
        print(f"{i}. {key}")
    print(f"{len(key_files) + 1}. 직접 입력")
    key_choice = input(f"선택 (1-{len(key_files) + 1}): ") or "1"
    identity_file = f"~/key/{key_files[int(key_choice) - 1]}" if int(key_choice) <= len(key_files) else input("경로 입력: ")

    config_path = os.path.expanduser("~/.ssh/config")
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(config_path, "a") as f:
        f.write(f"\n# Added by auto_ssh.py on {current_time}\n")
        f.write(f"\nHost {host}\n")
        f.write(f"    HostName {ip}\n")
        f.write(f"    User {user}\n")
        f.write(f"    Port {port}\n")
        f.write(f"    IdentityFile {identity_file}\n\n")
    print(f"{ip}:{port} ({host})이 .ssh/config에 추가되었습니다.")

# SSH 접속 확인 함수
def check_ssh_connection(host):
    config_path = os.path.expanduser("~/.ssh/config")
    ssh_config = SSHConfig()
    with open(config_path, "r") as f:
        ssh_config.parse(f)
    
    host_config = ssh_config.lookup(host)
    if not host_config:
        print(f"{host}에 대한 설정이 ~/.ssh/config에 없습니다.")
        return host, False, None
    
    hostname = host_config.get('hostname')
    user = host_config.get('user')
    port = host_config.get('port', 22)
    identityfile = host_config.get('identityfile')
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=hostname,
            username=user,
            port=int(port),
            key_filename=identityfile[0] if identityfile else None,
            timeout=5
        )
        client.close()
        print(f"- {host} : Connected OK")
        return host, True, None
    except Exception as e:
        return host, False, e

# 모든 호스트의 SSH 접속을 확인하는 함수
def check_ssh_connections():
    config_path = os.path.expanduser("~/.ssh/config")
    hosts = []
    with open(config_path, "r") as f:
        for line in f:
            if line.strip().startswith("Host "):
                hosts.append(line.strip().split()[1])

    failed_hosts = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_ssh_connection, hosts)
        for host, success, e in results:
            if not success:
                failed_hosts.append((host, e))
    
    if failed_hosts:
        print("Connection Failed Hosts:")
        for host, error in failed_hosts:
            print(f"{host} : {error}")
    else:
        print("All hosts connected successfully!")

# 기본 IP 대역을 가져오는 함수 (임시로 고정값 사용)
def get_default_ip_range():
    # 로컬 IP를 동적으로 가져옴
    local_ip = socket.gethostbyname(socket.gethostname())
    # /16 대역으로 네트워크 설정
    network = ipaddress.ip_network(f"{local_ip}/16", strict=False)
    return str(network)

# SSH 포트를 가져오는 함수 (임시로 고정값 사용)
def get_ssh_port():
    # 사용자 입력을 받고, 입력이 없으면 기본값 22 사용
    port = input("조회할 SSH 포트를 입력하세요 (기본값 22): ") or "22"
    return int(port)

# 메인 함수
def main():
    # 사용자가 언급한 코드 부분이 여기 포함됨!
    parser = argparse.ArgumentParser(description="SSH Config 자동 생성 스크립트")
    parser.add_argument("--check", action="store_true", help="SSH 접속 확인 실행")
    args = parser.parse_args()

    if args.check:
        check_ssh_connections()
    else:
        # IP 대역 설정
        default_ip_range = get_default_ip_range()
        ip_range_input = input(f"IP 대역을 입력하세요 (기본값 {default_ip_range}): ") or default_ip_range
        ip_range = ipaddress.ip_network(ip_range_input, strict=False)
        
        # SSH 포트 설정
        port = get_ssh_port()
        
        # 자기 자신의 IP 가져오기
        local_ip = socket.gethostbyname(socket.gethostname())
        
        print(f"Set IP Band : {ip_range}")
        print(f"Set SSH Port : {port}")

        # 기존에 등록된 IP 가져오기
        existing_ips = get_existing_hosts()
        
        # 제외할 IP: 자기 자신 + 기존 등록된 IP
        exclude_ips = set([local_ip]) | existing_ips
        
        # IP 스캔 실행
        open_ips = scan_ip_range(ip_range, port, exclude_ips)
        
        # 새로 추가할 IP 처리
        if open_ips:
            print("\nList of detected IPs:")
            for ip in open_ips:
                print(f" - {str(ip)}")
            
            for ip in open_ips:
                add_new_host(str(ip),port)
        else:
            print("No new IPs to add")

if __name__ == "__main__":
    main()
