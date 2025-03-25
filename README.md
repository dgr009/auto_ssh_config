# 🛠️ auto_ssh.py - 자동 SSH 구성 및 상태 점검 유틸리티

자동으로 EC2 등 SSH 가능한 서버를 검색하고, `~/.ssh/config`에 추가하거나, 현재 등록된 호스트의 SSH 접속 가능 여부를 확인하는 Python 기반 툴입니다.

---

## 🚀 주요 기능

- CIDR 대역을 스캔하여 SSH 가능한 서버 자동 등록
- `~/.ssh/config` 기반 등록 호스트들의 SSH 접속 상태 확인
- `paramiko`, `rich`, `dotenv` 등 실전용 고급 라이브러리 기반
- 로그 파일 자동 저장 (`logs/auto_ssh.log`)
- 인증 실패, 검증코드 등 예외 상황도 로깅

---

## 📦 의존 패키지

```bash
pip install -r requirements.txt

requirements.txt 예시

paramiko
tqdm
python-dotenv
rich



⸻

⚙️ 환경 변수 (.env)

.env 또는 시스템 환경변수로 아래 값을 설정할 수 있습니다:

변수명	설명	기본값
SSH_KEY_DIR	개인키 폴더 경로	~/aws-key
SSH_CONFIG_FILE	SSH config 경로	~/.ssh/config
SSH_MAX_WORKER	스레드 동시 처리 수	50
PORT_OPEN_TIMEOUT	포트 열림 확인 타임아웃	0.5
SSH_TIMEOUT	SSH 연결 타임아웃	3
LOG_LEVEL	전체 로그 레벨 (DEBUG, INFO…)	INFO



⸻

🧪 사용법

1. CIDR 범위 내 SSH 가능한 서버 자동 등록

python3 auto_ssh.py 192.168.0.0/24 --key ~/aws-key/my-key.pem

	•	CIDR 범위의 서버 중 포트 22가 열려있는 대상에 대해 SSH 접속을 시도하고
	•	호스트명을 얻어 ~/.ssh/config에 자동으로 추가합니다.

⸻

2. 기존 등록된 SSH 호스트 상태 점검

python3 auto_ssh.py --check

	•	~/.ssh/config에 등록된 모든 호스트에 대해 실제 SSH 접속을 시도합니다.
	•	실패한 호스트는 테이블로 출력되며, 검증코드가 필요한 경우도 예외로 표시됩니다.

⸻

🧾 출력 예시

✅ 신규 호스트 등록

┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃ IP               ┃ Hostname             ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│ 192.168.0.21     │ ip-192-168-0-21      │
│ 192.168.0.37     │ ip-192-168-0-37      │
└──────────────────┴──────────────────────┘

❌ SSH 접속 실패 호스트

┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Host         ┃ Error                            ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ staging-1    │ timed out                        │
│ bastion-03   │ Authentication failed            │
└──────────────┴──────────────────────────────────┘



⸻

📁 로그 파일
	•	모든 로깅은 logs/auto_ssh.log에 자동 저장됩니다.
	•	콘솔 출력을 끄고 로그만 저장하고 싶을 경우, --silent 기능을 향후 추가로 적용 가능. (update 예정)

⸻

💡 팁
	•	AWS, Oracle Cloud, 온프레미스 등 다양한 환경에서 활용 가능
	•	keyboard-interactive 인증 등 MFA 요구되는 경우 자동 패스 처리
	•	실서버 운영환경에서도 실수 없이 SSH 설정 가능하도록 설계됨

⸻

🧑‍💻 Author

개발자: [SYKIM]
문의: [cruiser594@gmail.com]

⸻

📝 License

MIT License

---

필요하다면 `README.md` 파일로 저장해서 바로 제공해드릴게요.  
또는 `--log-level`, `--silent` 같은 CLI 옵션이 추가되면 이에 맞게 바로 업데이트도 가능해요! 😎