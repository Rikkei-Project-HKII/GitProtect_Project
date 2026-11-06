import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.config import settings

class CryptoService:
    """
    Module mã hóa dữ liệu ở trạng thái nghỉ (at-rest) chuẩn AES-256-GCM (NFR-01, S1-01b).
    Mỗi lần mã hóa sinh một vector khởi tạo (IV/Nonce) 12 bytes ngẫu nhiên riêng biệt.
    Ciphertext lưu trữ định dạng: Base64(nonce_12b + ciphertext + auth_tag_16b).
    """
    def __init__(self, key_hex: str = None):
        key_raw = bytes.fromhex(key_hex or settings.AES_MASTER_KEY_HEX)
        if len(key_raw) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte (256-bit) key.")
        self.aesgcm = AESGCM(key_raw)

    def encrypt(self, plaintext: str) -> str:
        if not plaintext:
            return ""
        nonce = os.urandom(12)  # 96-bit unique IV
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.b64encode(nonce + ciphertext).decode("utf-8")

    def decrypt(self, encrypted_b64: str) -> str:
        if not encrypted_b64:
            return ""
        data = base64.b64decode(encrypted_b64)
        if len(data) < 28: # 12 bytes nonce + min 16 bytes tag
            raise ValueError("Invalid ciphertext length.")
        nonce, ciphertext = data[:12], data[12:]
        return self.aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

crypto_service = CryptoService()
