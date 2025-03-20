# SSH Config 자동 생성 스크립트

## 개요
이 스크립트는 지정된 IP 대역에서 SSH 포트(기본값: 22)가 열린 서버를 자동으로 검색하고, `~/.ssh/config` 파일에 새로운 호스트를 등록하는 기능을 수행합니다. 또한 기존에 등록된 SSH 호스트들의 접속 상태를 점검할 수 있습니다.

## 주요 기능
- **IP 대역 검색**: 지정된 IP 대역에서 SSH 포트가 열린 서버를 검색합니다.
- **SSH 설정 자동 추가**: 검색된 서버를 `~/.ssh/config` 파일에 자동으로 등록합니다.
- **SSH 접속 테스트**: `~/.ssh/config`에 등록된 호스트들의 SSH 접속 가능 여부를 확인합니다.

## 설치 및 실행 방법
### 1. 필요한 패키지 설치
스크립트 실행을 위해 아래 패키지가 필요합니다.

```bash
pip install paramiko tqdm
```

### 2. 실행 방법
```bash
python script.py
```

### 3. SSH 접속 확인 모드 실행
```bash
python script.py --check
```

## 환경 변수
| 환경 변수            | 기본값                | 설명                           |
|--------------------|---------------------|-------------------------------|
| `SSH_KEY_DIR`      | `~/aws-key`         | SSH 키 파일이 저장된 디렉토리       |
| `SSH_CONFIG_FILE`  | `~/.ssh/config`     | 병렬 처리를 위한 최대 스레드 수      |
| `SSH_MAX_WORKER`   | `100`               | 병렬 처리를 위한 최대 스레드 수      |
| `PORT_OPEN_TIMEOUT`| `0.5`               | 포트 열린 상태 체크 시 타임아웃(초)   |
| `SSH_TIMEOUT`      | `3`                 | SSH 연결 타임아웃(초)             |


## 상세 기능 설명
### 1. 기존 SSH 호스트 확인 (`get_existing_hosts()`)
- `~/.ssh/config` 파일에서 등록된 IP 주소를 읽어 기존에 등록된 호스트 목록을 생성합니다.

### 2. 포트 열린 상태 확인 (`is_port_open()`)
- 지정된 IP에서 특정 포트(기본: 22)가 열려 있는지 확인합니다.

### 3. IP 대역 스캔 (`scan_ip_range()`)
- 사용자가 입력한 IP 대역을 기준으로 SSH 포트가 열린 서버를 병렬로 검색합니다.

### 4. 새로운 SSH 호스트 추가 (`add_new_host()`)
- 스캔된 서버를 `~/.ssh/config`에 등록할 것인지 사용자에게 확인받고 추가합니다.
- SSH 사용자 및 키 파일을 선택할 수 있습니다.

### 5. SSH 접속 테스트 (`check_ssh_connection()` 및 `check_ssh_connections()`)
- `~/.ssh/config`에 등록된 모든 호스트에 대해 SSH 연결 테스트를 수행하고, 실패한 경우 오류 메시지를 출력합니다.

### 6. 기본 IP 대역 자동 감지 (`get_default_ip_range()`)
- 현재 호스트의 IP를 기반으로 `/16` 서브넷을 자동으로 설정합니다.

### 7. SSH 포트 설정 (`get_ssh_port()`)
- 기본 SSH 포트(22)를 사용하며, 사용자가 직접 변경할 수 있습니다.

## 실행 예시
### 1. IP 대역 검색 및 SSH 등록
```bash
python script.py
```
- 실행 후 IP 대역을 입력하면 해당 범위에서 SSH 포트가 열린 서버를 검색하고, 등록 여부를 확인합니다.

### 2. SSH 접속 확인 모드
```bash
python script.py --check
```
- `~/.ssh/config`에 등록된 모든 호스트에 대해 SSH 접속 가능 여부를 확인합니다.

## 결과 예시
### 1. 새로운 호스트 발견 시
```
Set IP Band : 192.168.1.0/24
Set SSH Port : 22
IP 스캔 진행 중: 100%|██████████| 254/254 [00:10<00:00, 24.9it/s]

List of detected IPs:
 - 192.168.1.10
 - 192.168.1.20

IP 192.168.1.10를 등록하시겠습니까?
선택 (1: 등록, 0: 등록 안 함, 기본값 0): 1
192.168.1.10의 호스트 이름을 입력하세요 (예: vm01): test-server
사용자를 선택하세요 (기본값 1):
1. ubuntu
2. rocky
3. ec2-user
4. centos
5. root
6. 직접 입력
선택 (1-6): 1
IdentityFile을 선택하세요:
1. my-key.pem
2. other-key.pem
3. 직접 입력
선택 (1-3): 1
192.168.1.10:22 (test-server)이 .ssh/config에 추가되었습니다.
```

### 2. SSH 접속 확인 결과
```
- test-server : Connected OK
- another-server : Connected OK
Connection Failed Hosts:
- failed-server : Authentication failed.
```

## 주의사항
- `~/.ssh/config` 파일을 직접 수정하므로 기존 설정이 유지되도록 주의하세요.
- 실행 전에 SSH 키 디렉토리를 환경 변수 `SSH_KEY_DIR`로 설정해 두는 것이 좋습니다.
- 검색하는 IP 대역이 너무 크면 속도가 느려질 수 있습니다.
- SSH 접속 테스트는 병렬 실행되므로 서버에 과부하가 걸리지 않도록 주의하세요.
- **Verification Code (2MFA)가 동작하는 서버가 config 파일에 포함될 경우 정상적인 작동이 불가능합니다.**

## 개선 가능 사항
- 다중 IP 대역 입력 기능 추가
- JSON 또는 YAML 설정 파일을 사용한 자동화
- GUI를 통한 SSH 설정 관리
- 2MFA 인증 서버 스킵 기능 추가 필요


