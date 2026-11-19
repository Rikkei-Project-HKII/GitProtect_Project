import json
import os

def generate_benchmark_dataset():
    samples = []

    # ================= 100 MẪU SECRET THẬT (TRUE POSITIVES) =================
    # 1. 20 mẫu GitHub PAT (RULE-01)
    for i in range(10):
        samples.append({
            "id": f"TP-PAT-{i+1:02d}",
            "type": "positive",
            "rule": "RULE-01",
            "file_path": f"src/config/github_client_{i}.py",
            "content": f'GITHUB_TOKEN = "ghp_AbC123Def456Ghi789Jkl012Mno345Pqr{i:03d}XyZ"\nclient.connect(GITHUB_TOKEN)',
            "expected_leaked": True,
            "description": "GitHub Classic PAT trong mã nguồn"
        })
    for i in range(10):
        samples.append({
            "id": f"TP-FINE-PAT-{i+1:02d}",
            "type": "positive",
            "rule": "RULE-01",
            "file_path": f"src/auth/service_{i}.py",
            "content": f'pat_token = "github_pat_11AB22CD33EF44GH55IJ66_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ{i:02d}"',
            "expected_leaked": True,
            "description": "GitHub Fine-grained PAT trong mã nguồn"
        })

    # 2. 15 mẫu Private Key Blocks (RULE-02)
    key_types = ["RSA", "EC", "OPENSSH", "DSA", "ENCRYPTED"]
    for i in range(15):
        ktype = key_types[i % len(key_types)]
        samples.append({
            "id": f"TP-KEY-{i+1:02d}",
            "type": "positive",
            "rule": "RULE-02",
            "file_path": f"keys/server_id_{i}.key",
            "content": f"-----BEGIN {ktype} PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m4wKh6X8n09182379182739182371928371928371298371\n-----END {ktype} PRIVATE KEY-----",
            "expected_leaked": True,
            "description": f"Khối {ktype} Private Key"
        })

    # 3. 20 mẫu Production .env assignments (RULE-03)
    env_keys = ["DATABASE_URL", "JWT_SECRET", "APP_SECRET_KEY", "STRIPE_SECRET_KEY"]
    for i in range(20):
        kname = env_keys[i % len(env_keys)]
        samples.append({
            "id": f"TP-ENV-{i+1:02d}",
            "type": "positive",
            "rule": "RULE-03",
            "file_path": ".env",
            "content": f'{kname}="postgres://user:super_secret_pw_{i:02d}@prod-db.internal:5432/main_db"',
            "expected_leaked": True,
            "description": f"Tập tin .env sản phẩm gán {kname}"
        })

    # 4. 15 mẫu AWS Access Key (RULE-04)
    for i in range(15):
        prefix = "AKIA" if i % 2 == 0 else "ASIA"
        samples.append({
            "id": f"TP-AWS-{i+1:02d}",
            "type": "positive",
            "rule": "RULE-04",
            "file_path": "deploy/aws_config.py",
            "content": f'AWS_ACCESS_KEY = "{prefix}IOSFODNN7{i:02d}ABCD5E"\nAWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEY{i:02d}"',
            "expected_leaked": True,
            "description": "AWS Access Key ID và Secret"
        })

    # 5. 15 mẫu CCCD Việt Nam (RULE-05)
    provinces = ["001", "079", "048", "092", "038"] # Hà Nội, TP.HCM, Đà Nẵng, Cần Thơ, Thanh Hóa
    for i in range(15):
        prov = provinces[i % len(provinces)]
        cccd_num = f"0{prov[1:]}0990123{i:02d}"
        samples.append({
            "id": f"TP-CCCD-{i+1:02d}",
            "type": "positive",
            "rule": "RULE-05",
            "file_path": f"users/profile_{i}.py",
            "content": f'# so can cuoc cong dan xac thuc identity\nuser_cccd = "{cccd_num}"; // CCCD hop le',
            "expected_leaked": True,
            "description": f"Số CCCD Việt Nam hợp lệ tỉnh {prov}"
        })

    # 6. 15 mẫu Slack/Discord Bot Token (RULE-06)
    for i in range(15):
        if i % 2 == 0:
            samples.append({
                "id": f"TP-BOT-{i+1:02d}",
                "type": "positive",
                "rule": "RULE-06",
                "file_path": "bot/slack_client.py",
                "content": f'SLACK_BOT_TOKEN = "xoxb-123456789012-987654321098-abcdefghijklmnopqrstuvwx{i:02d}"',
                "expected_leaked": True,
                "description": "Slack Bot Token (xoxb-)"
            })
        else:
            samples.append({
                "id": f"TP-BOT-{i+1:02d}",
                "type": "positive",
                "rule": "RULE-06",
                "file_path": "alerts/discord_hook.py",
                "content": f'WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-abcdef{i:02d}"',
                "expected_leaked": True,
                "description": "Discord Webhook Token"
            })

    # ================= 100 MẪU CHUỖI LÀNH TÍNH / AN TOÀN (TRUE NEGATIVES) =================
    # 1. 20 mẫu .env.example / .env.sample (Allowlist RULE-03)
    for i in range(20):
        fname = ".env.example" if i % 2 == 0 else ".env.sample"
        samples.append({
            "id": f"TN-ALLOWLIST-{i+1:02d}",
            "type": "negative",
            "rule": "ALLOWLIST",
            "file_path": fname,
            "content": f'DATABASE_URL="postgres://username:password@localhost:5432/sample_db_{i}"\nJWT_SECRET="your_sample_secret_key_here_{i:02d}"',
            "expected_leaked": False,
            "description": f"Tập tin mẫu {fname} chứa cấu hình giả định"
        })

    # 2. 20 mẫu Git Commit Hash vô hại (SHA-256)
    for i in range(20):
        samples.append({
            "id": f"TN-HASH-{i+1:02d}",
            "type": "negative",
            "rule": "SAFE_HASH",
            "file_path": "scripts/build_info.py",
            "content": f'git_commit = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85{i:02x}"',
            "expected_leaked": False,
            "description": "Chuỗi SHA-256 commit hash bình thường"
        })

    # 3. 20 mẫu Mock/Dummy Unit Test Data
    for i in range(20):
        samples.append({
            "id": f"TN-MOCK-{i+1:02d}",
            "type": "negative",
            "rule": "TEST_MOCK",
            "file_path": f"tests/test_auth_service_{i}.py",
            "content": f'const test_token = "dummy_mock_Zx8kLm29Qw7Rt5Uh3Vb6Nc4Yp1_{i:02d}";\nassert validate(test_token) is True',
            "expected_leaked": False,
            "description": "Dữ liệu mock/dummy trong thư mục test"
        })

    # 4. 20 mẫu Mã vận đơn / số 12 chữ số không có ngữ cảnh CCCD
    for i in range(20):
        samples.append({
            "id": f"TN-TRACKING-{i+1:02d}",
            "type": "negative",
            "rule": "INVALID_PII",
            "file_path": "shipping/logistics.py",
            "content": f'const tracking_code = "9994990123{i:02d}"; // ma van don chuyen phat nhanh bưu cục',
            "expected_leaked": False,
            "description": "Mã vận đơn 12 chữ số ngẫu nhiên không phải CCCD"
        })

    # 5. 20 mẫu Mã nguồn bình thường (UUID, URL, import statements)
    for i in range(20):
        samples.append({
            "id": f"TN-CODE-{i+1:02d}",
            "type": "negative",
            "rule": "NORMAL_CODE",
            "file_path": f"components/Widget_{i}.jsx",
            "content": f'import React from "react";\nconst component_id = "550e8400-e29b-41d4-a716-4466554400{i:02d}";\nexport default () => <div>Hello {i}</div>;',
            "expected_leaked": False,
            "description": "Đoạn mã React Component chứa UUID hợp lệ"
        })

    return samples

if __name__ == "__main__":
    dataset = generate_benchmark_dataset()
    print(f"Total samples: {len(dataset)}")
    pos = sum(1 for s in dataset if s["type"] == "positive")
    neg = sum(1 for s in dataset if s["type"] == "negative")
    print(f"Positives (Secrets): {pos}, Negatives (Safe): {neg}")

    # Ghi ra 2 thư mục benchmark
    out_paths = [
        "gitprotect_backend/tests/benchmark/dataset_200.json",
        "tests/benchmark_dataset_200.json",
    ]
    for p in out_paths:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(dataset, f, ensure_ascii=False, indent=2)
        print(f"Written: {p}")
