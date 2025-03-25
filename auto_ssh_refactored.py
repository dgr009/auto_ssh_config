
#!/usr/bin/env python3
"""자동 SSH 접속을 위한 유틸리티 스크립트입니다."""

import os
import socket
import ipaddress
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import paramiko
from paramiko.config import SSHConfig
from tqdm import tqdm
from dotenv import load_dotenv
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
import logging

# 환경 변수 로딩
load_dotenv()

# 콘솔 및 로거 설정
console = Console()
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,       # level of logging (INFO, WARN, ERROR)
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[
        RichHandler(rich_tracebacks=True),
        logging.FileHandler("logs/auto_ssh.log", mode='a', encoding='utf-8')
    ]
)
logger = logging.getLogger("auto-ssh")
paramiko_logger = logging.getLogger("paramiko")
paramiko_logger.setLevel(logging.WARNING)

# 환경 변수 설정
DEFAULT_KEY_DIR = os.getenv("SSH_KEY_DIR", os.path.expanduser("~/aws-key"))
SSH_CONFIG_FILE = os.getenv("SSH_CONFIG_FILE", os.path.expanduser("~/.ssh/config"))
SSH_MAX_WORKER = int(os.getenv("SSH_MAX_WORKER", 50))
PORT_OPEN_TIMEOUT = float(os.getenv("PORT_OPEN_TIMEOUT", 0.5))
SSH_TIMEOUT = float(os.getenv("SSH_TIMEOUT", 3))


def get_existing_hosts():
    """기존에 등록된 호스트 IP를 SSH 설정에서 불러옵니다."""
    existing_ips = set()
    try:
        if os.path.exists(SSH_CONFIG_FILE):
            with open(SSH_CONFIG_FILE, "r") as f:
                for line in f:
                    if "Hostname" in line:
                        ip = line.strip().split()[-1]
                        existing_ips.add(ip)
    except IOError as e:
        logger.exception("SSH 설정 파일 읽기 실패: %s", str(e))
        console.print(f"[bold red]SSH 설정 파일 읽기 실패:[/bold red] {e}")
    return existing_ips


def is_port_open(ip, port=22):
    """지정된 IP와 포트가 열려 있는지 확인합니다."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(PORT_OPEN_TIMEOUT)
        try:
            result = sock.connect_ex((str(ip), port))
            return result == 0
        except Exception as e:
            logger.debug("포트 확인 중 예외 발생: %s", str(e))
            return False


def generate_ip_range(cidr):
    """CIDR 범위 내 IP 목록을 생성합니다."""
    try:
        network = ipaddress.IPv4Network(cidr)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        logger.error("유효하지 않은 CIDR: %s", cidr)
        console.print(f"[bold red]CIDR 에러:[/bold red] {e}")
        return []


def get_hostname_via_ssh(ip, key_path):
    """SSH를 통해 호스트명(hostname)을 가져옵니다."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(str(ip), username="ec2-user", key_filename=key_path, timeout=SSH_TIMEOUT)
        stdin, stdout, stderr = ssh.exec_command("hostname")
        hostname = stdout.read().decode().strip()
        ssh.close()
        return hostname
    except Exception as e:
        logger.warning("SSH 실패 (%s): %s", ip, str(e))
        return None


def update_ssh_config(ip, hostname, key_path):
    """SSH 설정 파일에 새로운 호스트 항목을 추가합니다."""
    try:
        with open(SSH_CONFIG_FILE, "a") as f:
            f.write(f"\nHost {hostname}\n")
            f.write(f"    Hostname {ip}\n")
            f.write(f"    User ec2-user\n")
            f.write(f"    IdentityFile {key_path}\n")
        logger.info("SSH config 업데이트: %s (%s)", hostname, ip)
    except Exception as e:
        logger.error("SSH config 업데이트 실패: %s", str(e))


def scan_and_add_hosts(cidr, key_path):
    """CIDR 대역을 스캔하여 포트가 열려 있고 등록되지 않은 호스트를 추가합니다."""
    existing_hosts = get_existing_hosts()
    ip_list = generate_ip_range(cidr)
    results = []

    with ThreadPoolExecutor(max_workers=SSH_MAX_WORKER) as executor:
        futures = {
            executor.submit(is_port_open, ip): ip for ip in ip_list if ip not in existing_hosts
        }
        for future in tqdm(futures, desc="Scanning"):
            ip = futures[future]
            try:
                if future.result():
                    hostname = get_hostname_via_ssh(ip, key_path)
                    if hostname:
                        update_ssh_config(ip, hostname, key_path)
                        results.append({ "IP": ip, "Hostname": hostname })
            except Exception as e:
                logger.error("호스트 처리 중 오류 (%s): %s", ip, str(e))

    if results:
        table = Table(title="등록된 SSH 호스트")
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("Hostname", style="green")
        for entry in results:
            table.add_row(entry["IP"], entry["Hostname"])
        console.print(table)
    else:
        console.print("[yellow]새로 등록된 호스트가 없습니다.[/yellow]")


# def check_ssh_connection(host):
#     """단일 호스트에 대해 SSH 접속 가능 여부를 확인합니다."""
#     try:
#         ssh = paramiko.SSHClient()
#         ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         ssh.connect(host, username="ec2-user", timeout=SSH_TIMEOUT)
#         ssh.close()
#         return (host, True, None)
#     except Exception as e:
#         return (host, False, str(e))

# SSH 접속 확인 함수
def check_ssh_connection(host):
    config_path = os.path.expanduser(SSH_CONFIG_FILE)
    ssh_config = SSHConfig()
    with open(config_path, "r") as f:
        ssh_config.parse(f)
    
    host_config = ssh_config.lookup(host)
    if not host_config:
        return host, False, None
    
    hostname = host_config.get('hostname')
    user = host_config.get('user')
    port = int(host_config.get('port', 22))
    identityfile = host_config.get('identityfile')
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=hostname,
            username=user,
            port=port,
            key_filename=identityfile[0] if identityfile else None,
            timeout=SSH_TIMEOUT
        )
        client.close()
        return (host, True, None)

    except paramiko.ssh_exception.AuthenticationException as e:
        # e를 소문자로 변환
        error_str = str(e).lower()
        if "keyboard-interactive" in error_str or "Verification code" in error_str:
            # 여기서 바로 사용자 입력을 받지 않고,
            # "검증코드 필요 -> 접속 실패"로 처리하거나, 별도 목록에 넣음
            # print(f"- {host} : Verification needed (keyboard-interactive), skipped.")
            return (host, False, str(e))
        else:
            # print(f"- {host} : Authentication failed ({e})")
            return (host, False, str(e))

    except Exception as e:
        # print(f"- {host} : Connection error ({e})")
        return (host, False, str(e))

def check_ssh_connections():
    """SSH config에 정의된 모든 호스트의 연결 상태를 확인합니다."""
    config_path = os.path.expanduser(SSH_CONFIG_FILE)
    hosts = []

    try:
        with open(config_path, "r") as f:
            for line in f:
                if line.strip().startswith("Host "):
                    host = line.strip().split()[1]
                    if host != "*":
                        hosts.append(host)
    except Exception as e:
        logger.exception("SSH 설정 파일 읽기 실패: %s", e)
        console.print(f"[bold red]SSH 설정 파일 읽기 실패:[/bold red] {e}")
        return

    failed_hosts = []
    with ThreadPoolExecutor(max_workers=SSH_MAX_WORKER) as executor:
        results = executor.map(check_ssh_connection, hosts)
        for host, success, error in results:
            if not success:
                failed_hosts.append((host, error))

    if failed_hosts:
        table = Table(title="SSH 연결 실패 호스트", show_lines=True)
        table.add_column("Host", style="red")
        table.add_column("Error", style="yellow")
        for host, error in failed_hosts:
            table.add_row(host, error)
        console.print(table)
    else:
        console.print("[bold green]모든 호스트에 성공적으로 연결되었습니다.[/bold green]")

def main():
    parser = argparse.ArgumentParser(description="자동 SSH 호스트 스캐너")
    parser.add_argument("cidr", nargs="?", help="검색할 CIDR (예: 192.168.0.0/24)")
    parser.add_argument("--key", help="SSH 개인키 경로", default=os.path.join(DEFAULT_KEY_DIR, "default-key.pem"))
    parser.add_argument("--check", action="store_true", help="모든 SSH 호스트 연결 확인")

    args = parser.parse_args()

    if args.check:
        logger.info("모든 SSH 호스트 연결 상태 확인 시작")
        check_ssh_connections()
    elif args.cidr:
        logger.info("스캔 시작: %s", args.cidr)
        scan_and_add_hosts(args.cidr, args.key)
    else:
        console.print("[bold red]CIDR 또는 --check 옵션을 입력해주세요.[/bold red]")


if __name__ == "__main__":
    main()
