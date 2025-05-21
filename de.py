import os
import sys
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import struct
import traceback # Optional for detailed debugging

# --- Configuration ---
ENCRYPTED_EXTENSION = ".SAVED" # Must match the encryptor

# --- Embedded Attacker's Private Key ---
# (Copied from your provided ransomware_private_key.pem)
EMBEDDED_PRIVATE_KEY_PEM = """
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDCB3L1Dl2wGtWy
jwADXSNQ4VnXbGFG0iTSHTuJ3nd8NCY2XyNXq0IFSevSDWnJPcofiokOtP+wLYNY
Junlp0diVq/YO7Bl49clv4CLtcFqQ+dz/zTTWc2WC3Wxb8mo2t/38fXDIrRVwImu
lW20XZofhwHpsYzxKhRvkSb73WRmDtU4bEDdTx5n0GiWMHlNiPmbXE3hhA/CzIg6
Rgi7AxjYYn/JspxzryFbNASjDGh1B4ZBe3H/xPTHWQert9F/PvbAmVIybKWm0kq7
Uv+iGL0VcK26CKDa4uLrQ9V/+JRhx8nqESwBynCTOikBNDcinnBslkjleApl2vpB
FD+bJ2f5AgMBAAECggEAAcbX74TIyJesUIjk8QLxs3hGznVSfDepKOfl30yzVyay
mWGcZR1/OqVrRIaFKxe24bxO5jyz0TEPgHeFwYm7Onws+svMIRi5pAG5i3339hFG
Xa5u9Ub/nhG/i4cIp5ROg/qaG6X2FQlw8VFyulm3kzWVJ8bNkblHC+D+RITp2hHh
WROgJFts9Zb/zCG5QeO2Qza3q5wEzlEolnWPB8KENC+6aVE4fptQBYrmwN4KYPOI
udXtz6OBh1QIp3+WJbxEjelSPg5apzkm+0PFLKawYM5nnbBEV8NFymH/BCpRubsl
DkKENM1VZHlkLgJnyfou83Xu7WuEZB7lv2R2bjgmQQKBgQD3agCTlyxFiLOR3kPJ
p8kl0JYIlVMQOPZd0T2ySsgThQ/mOj/ohgwVxHXfHt/lndpytEO6G8Ve0Jw0KgX9
m2j0M20J5b/3ZuDZMwuf9swgvQPl7DJ/3fK5fTXFi2sW6sn+NQQVDB7+dbY2ZSKC
FJzPQzohGjpzkiuIymgc/k3eOQKBgQDIwy5Q+weSNoaEpywiMEslkRafl7i9Ro8g
tW8ludk+SzF/krKcHRG9o+SSf7q5IEPE9PhPFWZEL1bUBq8nGGUA0nAz4EhYeYHp
pj7C73M0Gjy3jeZTT8Bqaq4SciS0hnT0ihiRhKm1tAeWgt1gpHCtT5aJpkIzv6xM
0G5AE1nXwQKBgDY1NHEh4yJNBEMGdsW9DFZLsEOrK+rXACuoB6ODvPiB4+zmgFAa
5pTyWX0MT7QIdO9Czb/+C61teXv4ZR2eqk0u40oS24+CK+uKwpZGxYy6vRroOFxJ
rb+0Tk688DayNJWM2hseb8AC3Gxoljn3+C91JExSadIeiYlMB6mqkjcJAoGAcnu6
4bsEqkAlnWenJyfa8mU2PXPLiUO/Qquz4hOE6pz+cP06lQOOplHbeh8UX5UikCIR
pydQ1fkYznexUd37Wuilyy9OkgVYK+D9UTQywbdkgFeOzFtiIk0LTsGAZOF3uCs3
r2OzU0aCPTYK/51GE86azYvdnJzkqDkDZc6jIQECgYBXWWfVCC4cj+wpkxpyWPP1
CA6690igRgMFB8F9lBJgvCQsEUfPNryfZZNgyRK0nadxPYRp/S2xvUvP7lu15q6c
eopuvJVt1bpubo0KUZZ6xx7FlKzHhrMwnlCNauQU9rG+QLz4aTSiwuXmfoKSZNUe
ejxtd61Gv8AkVaRsP786cw==
-----END PRIVATE KEY-----
"""
# -----------------------------------------

# --- Function to load the embedded private key ---
def load_embedded_private_key():
    """Loads the RSA private key from the embedded PEM string."""
    # print("Debug: Attempting to load embedded private key...") # Uncomment for debug
    try:
        private_key = serialization.load_pem_private_key(
            EMBEDDED_PRIVATE_KEY_PEM.encode('utf-8'),
            password=None # Assuming the key is not password-protected
        )
        # print("Debug: Embedded private key loaded successfully.") # Uncomment for debug
        return private_key
    except ValueError as e:
        # Error likely due to malformed key data
        print(f"!!! FATAL ERROR !!!: Cannot load embedded private key. The key data in the script might be corrupted or invalid.")
        # print(f"Debug Details: {e}") # Uncomment for debug details
        return None
    except Exception as e:
        # Catch other potential loading errors
        print(f"!!! UNEXPECTED ERROR !!! loading embedded private key: {e}")
        # traceback.print_exc() # Uncomment for detailed debug
        return None

# --- Function to decrypt a single file using Hybrid Decryption ---
def hybrid_decrypt_single_file(encrypted_input_path, private_key):
    """Decrypts a file and returns the original path, or None on error."""
    # Derive original filename by removing the encrypted extension
    if not encrypted_input_path.lower().endswith(ENCRYPTED_EXTENSION.lower()):
        return None # Skip if it doesn't have the target extension
    decrypted_output_path = encrypted_input_path[:-len(ENCRYPTED_EXTENSION)]
    # print(f"[*] Attempting Decryption: {encrypted_input_path} -> {decrypted_output_path}") # Uncomment for debug

    # Prevent accidentally overwriting an existing original file
    if os.path.exists(decrypted_output_path):
        print(f"    [!] Warning: Original file '{decrypted_output_path}' already exists. Skipping decryption for this file.")
        return None

    try:
        # 1. Read the encrypted file structure
        try:
            with open(encrypted_input_path, "rb") as enc_file:
                # Read the length of the encrypted session key (4 bytes)
                packed_len = enc_file.read(4)
                if len(packed_len) < 4:
                    print(f"    [!] Error: Invalid file format (too short for key length) in {encrypted_input_path}.")
                    return None
                encrypted_session_key_len = struct.unpack('>I', packed_len)[0]

                # Read the encrypted session key
                encrypted_session_key = enc_file.read(encrypted_session_key_len)
                if len(encrypted_session_key) < encrypted_session_key_len:
                    print(f"    [!] Error: Invalid file format (incomplete session key) in {encrypted_input_path}.")
                    return None

                # Read the rest of the file as the encrypted data
                encrypted_data = enc_file.read()
                if not encrypted_data:
                    print(f"    [!] Error: Invalid file format (missing encrypted data) in {encrypted_input_path}.")
                    return None
        except IOError as e:
            print(f"    [!] Error reading encrypted file {encrypted_input_path}: {e}. Skipping.")
            return None

        # 2. Decrypt the session key using the embedded private RSA key
        try:
            session_key = private_key.decrypt(
                encrypted_session_key,
                padding.OAEP( # MUST use the same padding scheme as encryption
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except ValueError:
             # This is the MOST LIKELY error if the private key is WRONG or the session key data is corrupt
             print(f"    [!] CRITICAL DECRYPTION ERROR: Could not decrypt session key for {encrypted_input_path}.")
             print( "        This usually means the EMBEDDED PRIVATE KEY is INCORRECT for this file, or the file is corrupt.")
             return None
        except Exception as e:
             print(f"    [!] Unexpected error decrypting session key for {encrypted_input_path}: {e}")
             return None

        # 3. Decrypt the actual file data using the recovered session key
        try:
            f = Fernet(session_key)
            decrypted_data = f.decrypt(encrypted_data)
            # print("    -> File data decrypted successfully.") # Uncomment for debug
        except InvalidToken:
            # This usually happens if the session key was wrong, or the encrypted_data is corrupt
            print(f"    [!] DECRYPTION FAILED: Invalid token for {encrypted_input_path}. Session key might be wrong or data corrupted.")
            return None
        except Exception as e:
            print(f"    [!] Unexpected error during Fernet decryption for {encrypted_input_path}: {e}")
            return None

        # 4. Write the decrypted data to the original filename
        try:
            with open(decrypted_output_path, "wb") as file:
                file.write(decrypted_data)
            print(f"    [+] SUCCESS: File restored to: {decrypted_output_path}")
        except IOError as e:
            print(f"    [!] Error writing decrypted file {decrypted_output_path}: {e}.")
            # Attempt to remove partially written file on error
            if os.path.exists(decrypted_output_path):
                try: os.remove(decrypted_output_path)
                except: pass
            return None # Failed to write decrypted file

        # 5. Delete the encrypted file *AFTER* successful decryption and writing
        try:
            os.remove(encrypted_input_path)
            # print(f"    -> Encrypted file deleted: {encrypted_input_path}") # Uncomment for debug
        except OSError as e:
            print(f"    [!] Warning: Could not delete encrypted file {encrypted_input_path}: {e}")
            # Decryption succeeded, but the encrypted file remains.
            pass

        return decrypted_output_path # Return the original file path on success

    except Exception as e:
        # Catch unexpected errors during the decryption process for this file
        print(f"[!] UNEXPECTED ERROR decrypting {encrypted_input_path}: {e}")
        # traceback.print_exc() # Uncomment for detailed debug
        # Attempt to clean up the potentially created output file if error occurred mid-process
        if 'decrypted_output_path' in locals() and os.path.exists(decrypted_output_path):
            try: os.remove(decrypted_output_path)
            except: pass
        return None # Indicate failure for this file


# --- Main function to scan and decrypt files ---
def decrypt_target_files(private_key):
    """Scans the Desktop for encrypted files and decrypts them."""
    decrypted_count = 0
    error_count = 0
    skipped_count = 0
    desktop_path = None
    try:
        # Find the Desktop path
        if 'USERPROFILE' in os.environ: # Windows
            desktop_path = os.path.join(os.environ['USERPROFILE'], 'Desktop')
        elif 'HOME' in os.environ: # Linux/macOS
             desktop_path = os.path.join(os.environ['HOME'], 'Desktop')
        else: # Fallback
            desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')

        if not os.path.isdir(desktop_path):
            print(f"!!! ERROR !!!: Cannot find Desktop directory: {desktop_path}")
            return False # Cannot proceed

        print(f"[*] Scanning Desktop for '{ENCRYPTED_EXTENSION}' files: {desktop_path}")
        print("-" * 60)

        # Iterate through items directly on the Desktop
        items_on_desktop = os.listdir(desktop_path)
        found_encrypted = False
        for item in items_on_desktop:
            item_path = os.path.join(desktop_path, item)
            # Check if it's a file and has the encrypted extension
            if os.path.isfile(item_path) and item_path.lower().endswith(ENCRYPTED_EXTENSION.lower()):
                found_encrypted = True
                # print(f"    -> Found encrypted file: {item}") # Uncomment for debug
                result = hybrid_decrypt_single_file(item_path, private_key)
                if result:
                    decrypted_count += 1
                elif os.path.exists(item_path[:-len(ENCRYPTED_EXTENSION)]): # Check if skipped due to existing original
                     skipped_count +=1
                else: # Genuine error during decryption
                     error_count += 1

        if not found_encrypted:
             print("[*] No files with the extension '{}' were found on the Desktop.".format(ENCRYPTED_EXTENSION))

        print("-" * 60)
        print(f"[*] Decryption process finished.")
        print(f"    - Files successfully decrypted: {decrypted_count}")
        print(f"    - Files skipped (original already exists): {skipped_count}")
        print(f"    - Files failed to decrypt (error/corruption): {error_count}")
        if error_count > 0:
             print("[!] WARNING: Some files could not be decrypted. This might be due to file corruption or an incorrect private key.")
        print("-" * 60)
        return True

    except Exception as e:
        print(f"[!!!] CRITICAL ERROR during scanning/decryption process: {e}")
        # traceback.print_exc() # Uncomment for detailed debug
        return False

# --- Script Execution Start ---
if __name__ == "__main__":
    print("--- Ransomware Decryption Tool (Embedded Key Version) ---")
    print("This tool will attempt to decrypt files with the extension")
    print(f"'{ENCRYPTED_EXTENSION}' found on your Desktop using the embedded private key.")
    print("=" * 60)

    # Load the embedded private key
    attacker_private_key = load_embedded_private_key()

    if attacker_private_key:
        # Start the decryption process
        decrypt_target_files(attacker_private_key)
    else:
        print("\n[!] Could not load the embedded private key. Decryption cannot proceed.")
        print("[!] Please ensure the decryptor tool itself is not corrupted.")

    print("\nPress Enter to exit.")
    input() # Keep window open
    sys.exit(0)