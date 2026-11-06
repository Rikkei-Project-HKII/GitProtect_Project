"""
GitProtect MVP (v1.1 Baseline - GP-2026-SCRUM)
Task S1-01b: Module Mã Hóa CryptoService Chuẩn AES-256-GCM (NFR-01, PBI-04)
Phụ trách: TV1 (Huỳnh Công Danh - Product Owner & Backend/DB Lead)
Bàn giao cho: TV2 tích hợp vào API kết nối repo GitHub PAT (Task S1-03d)

Đặc tả kỹ thuật bảo mật NFR-01:
1. Thuật toán: AES-256-GCM (Galois/Counter Mode) cung cấp tính bí mật (confidentiality)
   và tính toàn vẹn xác thực (integrity & authenticity - chống sửa đổi ciphertext).
2. Độ dài khóa: 256 bits (32 bytes). Khóa chính (Master Key) đọc từ biến môi trường
   `GITPROTECT_AES_MASTER_KEY` hoặc truyền qua constructor.
3. Vector khởi tạo (IV / Nonce): 96 bits (12 bytes) ngẫu nhiên bằng `os.urandom(12)`.
   QUAN TRỌNG: Mỗi lần mã hóa một bản ghi PAT hoặc Webhook Secret, hệ thống BẮT BUỘC sinh một IV
   riêng biệt, tuyệt đối không bao giờ tái sử dụng IV trên cùng một khóa bí mật.
4. Authentication Tag (Tag): 128 bits (16 bytes) được thư viện sinh tự động và gắn liền sau ciphertext.
5. Cấu trúc đóng gói lưu trữ vào CSDL MySQL (trường `access_token_encrypted`, `webhook_secret_encrypted`):
   `Ciphertext Payload = Base64(nonce_12b + ciphertext + auth_tag_16b)`
   Chuỗi lưu trữ là ASCII Base64 an toàn tuyệt đối cho kiểu cột TEXT trong MySQL 8.
"""

from __future__ import annotations

import base64
import os
import secrets
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise ImportError(
        "Thư viện 'cryptography' chưa được cài đặt. Vui lòng chạy: pip install cryptography"
    )

try:
    from app.core.config import settings
except ImportError:
    settings = None


class CryptoService:
    """
    Dịch vụ mã hóa và giải mã dữ liệu nhạy cảm ở trạng thái nghỉ (at-rest)
    bằng thuật toán AES-256-GCM kèm vector khởi tạo (IV) riêng biệt cho từng bản ghi.
    """

    NONCE_BYTE_SIZE: int = 12  # 96-bit chuẩn khuyến nghị của NIST cho GCM
    KEY_BYTE_SIZE: int = 32    # 256-bit key cho AES-256
    TAG_BYTE_SIZE: int = 16    # 128-bit authentication tag

    def __init__(self, master_key_hex: Optional[str] = None, *, key_hex: Optional[str] = None) -> None:
        """
        Khởi tạo CryptoService với Master Key 256-bit (dạng 64 ký tự Hex).
        Nếu không truyền trực tiếp, dịch vụ sẽ đọc từ biến môi trường `GITPROTECT_AES_MASTER_KEY`
        hoặc cấu hình settings trong dự án.
        """
        raw_hex = (
            master_key_hex
            or key_hex
            or os.getenv("GITPROTECT_AES_MASTER_KEY")
            or getattr(settings, "AES_MASTER_KEY_HEX", None)
            or os.getenv("AES_MASTER_KEY_HEX")
        )
        if not raw_hex:
            # Fallback dùng dev key mặc định phục vụ chạy thử nghiệm cục bộ
            raw_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        clean_hex = raw_hex.strip()
        try:
            self._key_bytes = bytes.fromhex(clean_hex)
        except ValueError as err:
            raise ValueError(
                f"Master Key không hợp lệ (phải là chuỗi Hex 64 ký tự hợp lệ): {err}"
            ) from err

        if len(self._key_bytes) != self.KEY_BYTE_SIZE:
            raise ValueError(
                f"Master Key phải có độ dài đúng 32 bytes (256 bits). Độ dài hiện tại: {len(self._key_bytes)} bytes."
            )

        self._aesgcm = AESGCM(self._key_bytes)

    @classmethod
    def generate_master_key_hex(cls) -> str:
        """Sinh ngẫu nhiên một Master Key 256-bit an toàn dạng chuỗi Hex 64 ký tự."""
        return secrets.token_hex(cls.KEY_BYTE_SIZE)

    def encrypt(self, plaintext: str, associated_data: Optional[bytes] = None) -> str:
        """
        Mã hóa chuỗi ký tự plaintext thành chuỗi Base64 an toàn.

        Args:
            plaintext: Chuỗi ký tự cần mã hóa (GitHub PAT, Webhook Secret).
            associated_data: Dữ liệu xác thực bổ sung AAD (nếu có).

        Returns:
            Chuỗi Base64 đại diện cho `nonce (12b) + ciphertext + tag (16b)`.
        """
        if plaintext is None:
            raise ValueError("Không thể mã hóa giá trị None.")
        if not isinstance(plaintext, str):
            plaintext = str(plaintext)

        plaintext_bytes = plaintext.encode("utf-8")
        # Sinh IV/Nonce ngẫu nhiên và duy nhất cho mỗi bản ghi (NIST SP 800-38D)
        nonce = os.urandom(self.NONCE_BYTE_SIZE)

        # AESGCM.encrypt trả về ciphertext kèm auth tag 16 bytes ở cuối
        ciphertext_with_tag = self._aesgcm.encrypt(nonce, plaintext_bytes, associated_data)

        # Đóng gói: [12 bytes IV] + [Ciphertext + 16 bytes Tag]
        payload = nonce + ciphertext_with_tag
        return base64.b64encode(payload).decode("utf-8")

    def decrypt(self, encrypted_b64: str, associated_data: Optional[bytes] = None) -> str:
        """
        Giải mã chuỗi Base64 về chuỗi ký tự plaintext ban đầu.

        Args:
            encrypted_b64: Chuỗi Base64 lưu trữ trong CSDL.
            associated_data: Dữ liệu xác thực bổ sung AAD (phải khớp khi mã hóa).

        Returns:
            Chuỗi plaintext ban đầu.

        Raises:
            ValueError: Nếu chuỗi mã hóa bị rỗng, sai định dạng Base64 hoặc độ dài không hợp lệ.
            cryptography.exceptions.InvalidTag: Nếu ciphertext hoặc tag bị chỉnh sửa/giả mạo.
        """
        if not encrypted_b64:
            raise ValueError("Chuỗi ciphertext rỗng, không thể giải mã.")

        try:
            payload = base64.b64decode(encrypted_b64, validate=True)
        except Exception as err:
            raise ValueError(f"Dữ liệu ciphertext không phải định dạng Base64 hợp lệ: {err}") from err

        min_required_len = self.NONCE_BYTE_SIZE + self.TAG_BYTE_SIZE
        if len(payload) < min_required_len:
            raise ValueError(
                f"Độ dài ciphertext không hợp lệ ({len(payload)} bytes < tối thiểu {min_required_len} bytes)."
            )

        # Tách vector khởi tạo IV và ciphertext + tag
        nonce = payload[:self.NONCE_BYTE_SIZE]
        ciphertext_with_tag = payload[self.NONCE_BYTE_SIZE:]

        decrypted_bytes = self._aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return decrypted_bytes.decode("utf-8")

    def mask_secret(self, secret: str, visible_suffix_len: int = 4) -> str:
        """
        Tiện ích tạo mặt nạ dữ liệu (Data Masking) theo quy chuẩn NFR-01:
        Định dạng: tiền tố nhận diện + '****' + visible_suffix_len ký tự cuối.
        Ví dụ: 'ghp_1234567890abcdef1234' -> 'ghp_****1234'
        """
        if not secret:
            return ""
        if len(secret) <= visible_suffix_len + 4:
            return "****"

        # Tự động nhận diện tiền tố thông dụng nếu có
        prefixes = ["ghp_", "github_pat_", "xoxb-", "AKIA", "ASIA"]
        prefix = ""
        for p in prefixes:
            if secret.startswith(p):
                prefix = p
                break

        suffix = secret[-visible_suffix_len:]
        return f"{prefix}****{suffix}"


# Singleton instance sẵn sàng import trực tiếp trong dự án
crypto_service = CryptoService()


# ============================================================================
# SELF-TEST & VERIFICATION SUITE (Chạy trực tiếp file để kiểm tra tính năng)
# ============================================================================
if __name__ == "__main__":
    from cryptography.exceptions import InvalidTag

    print("=== BẮT ĐẦU KIỂM THỬ MODULE CRYPTOSERVICE (S1-01b) ===")

    # Test 1: Khởi tạo với Master Key ngẫu nhiên
    key_hex = CryptoService.generate_master_key_hex()
    service = CryptoService(master_key_hex=key_hex)
    print(f"[PASS] 1. Khởi tạo Master Key 256-bit: {key_hex[:16]}... (64 hex chars)")

    # Test 2: Mã hóa & Giải mã GitHub PAT thật
    sample_pat = "ghp_Th1sIsAFak3G1thubP3rs0nalAcc3ssT0k3n"
    enc_pat = service.encrypt(sample_pat)
    dec_pat = service.decrypt(enc_pat)
    assert dec_pat == sample_pat, "Giải mã PAT không khớp!"
    print(f"[PASS] 2. Mã hóa & Giải mã PAT thành công:")
    print(f"         Plaintext:  {sample_pat}")
    print(f"         Ciphertext: {enc_pat[:32]}... (Base64)")

    # Test 3: Đảm bảo tính ngẫu nhiên của IV (Hai lần mã hóa cùng dữ liệu PHẢI ra 2 chuỗi khác nhau)
    enc_pat_2 = service.encrypt(sample_pat)
    assert enc_pat != enc_pat_2, "LỖI BẢO MẬT: IV bị tái sử dụng trên cùng một dữ liệu!"
    assert service.decrypt(enc_pat_2) == sample_pat
    print("[PASS] 3. Tính duy nhất của IV: Cùng một PAT mã hóa 2 lần sinh 2 ciphertext hoàn toàn khác nhau.")

    # Test 4: Chống giả mạo / phát hiện sửa đổi dữ liệu (Authentication Tag Tampering Check)
    raw_payload = bytearray(base64.b64decode(enc_pat))
    raw_payload[-1] ^= 0xFF  # Làm sai lệch 1 bit ở Auth Tag
    tampered_b64 = base64.b64encode(raw_payload).decode("utf-8")
    try:
        service.decrypt(tampered_b64)
        raise AssertionError("LỖI: Không phát hiện được ciphertext bị giả mạo!")
    except InvalidTag:
        print("[PASS] 4. Tính toàn vẹn GCM: Phát hiện và chặn đứng dữ liệu bị sửa đổi (InvalidTag).")

    # Test 5: Hàm tiện ích che dữ liệu (Data Masking)
    masked = service.mask_secret(sample_pat)
    assert masked.startswith("ghp_****") and masked.endswith(sample_pat[-4:])
    print(f"[PASS] 5. Mặt nạ dữ liệu Data Masking: {sample_pat} -> {masked}")

    print("=== TẤT CẢ CÁC BÀI TEST S1-01b ĐÃ VƯỢT QUA 100% ===")
