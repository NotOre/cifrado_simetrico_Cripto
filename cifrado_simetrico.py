from Cryptodome.Cipher import DES, AES, DES3
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import binascii


ALGORITHM_PARAMS = {
    "DES": {"key_size": 8, "iv_size": 8, "block_size": 8},
    "AES-256": {"key_size": 32, "iv_size": 16, "block_size": 16},
    "3DES": {"key_size": 24, "iv_size": 8, "block_size": 8},
}

def adjust_key(algorithm_name, key_input):
    
    required_size = ALGORITHM_PARAMS[algorithm_name]["key_size"]
    key_bytes = key_input.encode('utf-8')

    if len(key_bytes) < required_size:
        padding_needed = required_size - len(key_bytes)
        adjusted_key = key_bytes + get_random_bytes(padding_needed)
        print(f"  [!] Clave ajustada (rellenada con {padding_needed} bytes aleatorios).")
        
    elif len(key_bytes) > required_size:
        adjusted_key = key_bytes[:required_size]
        print(f"  [!] Clave ajustada (truncada).")
        
    else:
        adjusted_key = key_bytes
        print(f"  [+] Longitud de clave correcta.")

    print(f"  Clave final ({len(adjusted_key)} bytes): {binascii.hexlify(adjusted_key).decode('utf-8')}")
    return adjusted_key

def get_user_input(prompt, is_key=False, algorithm_name=None):

    while True:
        user_input = input(prompt)
        
        if is_key:
            return adjust_key(algorithm_name, user_input)
            
        else:
            return user_input.encode('utf-8') # Convertir a bytes para IV y texto

def encrypt_decrypt_des(key, iv, plaintext):

    print("\n--- Cifrado/Descifrado DES ---")
    block_size = ALGORITHM_PARAMS["DES"]["block_size"]

    cipher_des = DES.new(key, DES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, block_size)
    ciphertext = cipher_des.encrypt(padded_plaintext)
    print(f"  Texto cifrado (DES): {binascii.hexlify(ciphertext).decode('utf-8')}")

    cipher_des_decrypt = DES.new(key, DES.MODE_CBC, iv)
    decrypted_text_padded = cipher_des_decrypt.decrypt(ciphertext)
    decrypted_text = unpad(decrypted_text_padded, block_size)
    print(f"  Texto descifrado (DES): {decrypted_text.decode('utf-8')}")
    return ciphertext, decrypted_text

def encrypt_decrypt_aes256(key, iv, plaintext):

    print("\n--- Cifrado/Descifrado AES-256 ---")
    block_size = ALGORITHM_PARAMS["AES-256"]["block_size"]

    cipher_aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, block_size)
    ciphertext = cipher_aes.encrypt(padded_plaintext)
    print(f"  Texto cifrado (AES-256): {binascii.hexlify(ciphertext).decode('utf-8')}")

    cipher_aes_decrypt = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text_padded = cipher_aes_decrypt.decrypt(ciphertext)
    decrypted_text = unpad(decrypted_text_padded, block_size)
    print(f"  Texto descifrado (AES-256): {decrypted_text.decode('utf-8')}")
    return ciphertext, decrypted_text

def encrypt_decrypt_3des(key, iv, plaintext):

    print("\n--- Cifrado/Descifrado 3DES ---")
    block_size = ALGORITHM_PARAMS["3DES"]["block_size"]

    cipher_3des = DES3.new(key, DES3.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, block_size)
    ciphertext = cipher_3des.encrypt(padded_plaintext)
    print(f"  Texto cifrado (3DES): {binascii.hexlify(ciphertext).decode('utf-8')}")

    cipher_3des_decrypt = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_text_padded = cipher_3des_decrypt.decrypt(ciphertext)
    decrypted_text = unpad(decrypted_text_padded, block_size)
    print(f"  Texto descifrado (3DES): {decrypted_text.decode('utf-8')}")
    return ciphertext, decrypted_text

def main():
    print("Bienvenido al programa de cifrado/descifrado simétrico (DES, AES-256, 3DES)\n")

    plaintext_input = input("Ingrese el texto a cifrar: ").encode('utf-8')

    print("\n[CONFIGURACIÓN DES]")
    key_des = get_user_input("Ingrese la clave para DES (8 bytes): ", is_key=True, algorithm_name="DES")

    iv_des_raw = get_user_input("Ingrese el IV para DES (8 bytes, exactamente 8 caracteres): ")
    while len(iv_des_raw) != ALGORITHM_PARAMS["DES"]["iv_size"]:
        print(f"  [!] El IV para DES debe ser de {ALGORITHM_PARAMS['DES']['iv_size']} bytes.")
        iv_des_raw = get_user_input(f"Ingrese el IV para DES ({ALGORITHM_PARAMS['DES']['iv_size']} bytes, exactamente {ALGORITHM_PARAMS['DES']['iv_size']} caracteres): ")
    iv_des = iv_des_raw
    encrypt_decrypt_des(key_des, iv_des, plaintext_input)

    print("\n[CONFIGURACIÓN AES-256]")
    key_aes = get_user_input("Ingrese la clave para AES-256 (32 bytes): ", is_key=True, algorithm_name="AES-256")

    iv_aes_raw = get_user_input("Ingrese el IV para AES-256 (16 bytes, exactamente 16 caracteres): ")
    while len(iv_aes_raw) != ALGORITHM_PARAMS["AES-256"]["iv_size"]:
        print(f"  [!] El IV para AES-256 debe ser de {ALGORITHM_PARAMS['AES-256']['iv_size']} bytes.")
        iv_aes_raw = get_user_input(f"Ingrese el IV para AES-256 ({ALGORITHM_PARAMS['AES-256']['iv_size']} bytes, exactamente {ALGORITHM_PARAMS['AES-256']['iv_size']} caracteres): ")
    iv_aes = iv_aes_raw
    encrypt_decrypt_aes256(key_aes, iv_aes, plaintext_input)

    print("\n[CONFIGURACIÓN 3DES]")
    key_3des = get_user_input("Ingrese la clave para 3DES (24 bytes, recomendado): ", is_key=True, algorithm_name="3DES")

    iv_3des_raw = get_user_input("Ingrese el IV para 3DES (8 bytes, exactamente 8 caracteres): ")
    while len(iv_3des_raw) != ALGORITHM_PARAMS["3DES"]["iv_size"]:
        print(f"  [!] El IV para 3DES debe ser de {ALGORITHM_PARAMS['3DES']['iv_size']} bytes.")
        iv_3des_raw = get_user_input(f"Ingrese el IV para 3DES ({ALGORITHM_PARAMS['3DES']['iv_size']} bytes, exactamente {ALGORITHM_PARAMS['3DES']['iv_size']} caracteres): ")
    iv_3des = iv_3des_raw
    encrypt_decrypt_3des(key_3des, iv_3des, plaintext_input)

if __name__ == "__main__":
    main()
