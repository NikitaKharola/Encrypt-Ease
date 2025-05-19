from Crypto.Cipher import AES, PKCS1_OAEP                   # 🔒 AES is for symmetric encryption (e.g., encrypting your message),
                                                            # 🔐 PKCS1_OAEP is a secure padding scheme for RSA (used to encrypt AES key + CT1)
from Crypto.PublicKey import RSA, ECC                       # 🔑 RSA: used to generate public/private RSA key pairs for asymmetric encryption,
                                                            # 📐 ECC: used to perform Elliptic Curve Diffie-Hellman (ECDH) for AES key exchange
from Crypto.Random import get_random_bytes                   # 🎲 Used to generate secure random values — e.g., AES nonce or AES key 
from Crypto.Hash import SHA256                              # 🧂 Used as the hash function inside HKDF (for deriving AES key from shared ECC secret)
from Crypto.Protocol.KDF import HKDF                        # 🔁 HKDF = Key Derivation Function used to turn the shared ECC secret into a 16-byte AES key
import base64                                                # For encoding/decoding binary data to base64 for web transfer

def generate_dh_shared_key():                                # Performs ECDH key exchange and derives AES key from shared secret
    receiver_priv = ECC.generate(curve='P-256')              # Receiver's ECC private key using P-256 curve
    sender_priv = ECC.generate(curve='P-256')                # Sender's ECC private key
    receiver_pub = receiver_priv.public_key()                # Receiver's ECC public key
    sender_pub = sender_priv.public_key()                    # Sender's ECC public key

    shared_secret_receiver = receiver_priv.d * sender_pub.pointQ   # Receiver computes shared ECC point using sender's public key
    shared_secret_sender = sender_priv.d * receiver_pub.pointQ     # Sender does the same using receiver's public key (should match)

    def derive_key(shared_point):                            # Derives symmetric AES key from shared ECC point
        x = int(shared_point.x)                              # Extract x-coordinate of shared ECC point
        raw = x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')  # Convert x-coordinate to byte format
        return HKDF(master=raw, key_len=16, salt=None, hashmod=SHA256, context=b'', num_keys=1)  # Derive 128-bit AES key using HKDF

    shared_key = derive_key(shared_secret_receiver)          # Derive AES key using receiver's view of shared secret
    return shared_key, receiver_pub, sender_pub              # Return AES key, receiver's ECC pub key, sender's ECC pub key

def generate_rsa_keys():                                     # Generates a fresh RSA key pair
    key = RSA.generate(2048)                                 # Generate 2048-bit RSA private key
    return key.publickey(), key                              # Return corresponding public key and private key

def generate_keys_encrypt(plain_text):                       # Hybrid encryption: ECDH for AES key, AES to encrypt message, RSA to encrypt key+msg
    shared_aes_key, receiver_dh_pub, sender_dh_pub = generate_dh_shared_key()  # Get shared AES key from ECDH
    rsa_pub, rsa_priv = generate_rsa_keys()                  # Generate RSA public/private key pair
    aes_cipher = AES.new(shared_aes_key, AES.MODE_EAX)       # Initialize AES cipher in EAX mode for authenticated encryption
    ct1, tag = aes_cipher.encrypt_and_digest(plain_text.encode())  # Encrypt plaintext and generate tag

    rsa_cipher = PKCS1_OAEP.new(rsa_pub)                     # Initialize RSA cipher with public key
    combined = shared_aes_key + ct1                          # Concatenate AES key and AES-encrypted message
    ct2 = rsa_cipher.encrypt(combined)                       # Encrypt combined data with RSA to form ct2

    return {
        "ct2": base64.b64encode(ct2).decode(),               # Base64-encoded RSA ciphertext (AES key + AES message)
        "public_key": rsa_pub.export_key().decode(),         # Export RSA public key as string
        "private_key": rsa_priv.export_key().decode(),       # Export RSA private key as string
        "nonce": base64.b64encode(aes_cipher.nonce).decode(),# Base64-encoded AES nonce (needed for decryption)
        "tag": base64.b64encode(tag).decode()                # Base64-encoded AES tag (to verify message integrity)
    }

def decrypt_ct2_to_ct1(ct2_b64, private_key_pem):            # Decrypts RSA ciphertext to recover AES key and AES ciphertext
    try:
        ct2 = base64.b64decode(ct2_b64)                      # Decode RSA ciphertext from base64
        private_key = RSA.import_key(private_key_pem)        # Load RSA private key
        rsa_decipher = PKCS1_OAEP.new(private_key)           # Initialize RSA decryption
        decrypted = rsa_decipher.decrypt(ct2)                # Decrypt RSA ciphertext to get AES key + AES ciphertext

        aes_key = decrypted[:16]                             # Extract first 16 bytes as AES key
        ct1 = decrypted[16:]                                 # Remaining bytes are AES-encrypted message

        return {
            "ct1": base64.b64encode(ct1).decode(),           # Return AES ciphertext (base64)
            "aes_key_recovered": base64.b64encode(aes_key).decode(),  # Return recovered AES key (base64)
            "success_ct2": True                              # Flag indicating successful RSA decryption
        }
    except:
        return {"error_ct2": "❌ CT2 decryption failed. Invalid private key or CT2."}  # Handle failure gracefully

def decrypt_ct1_to_pt(ct1_b64, aes_key_b64, nonce_b64, tag_b64):  # Final AES decryption step to recover plaintext
    try:
        ct1 = base64.b64decode(ct1_b64)                    # Decode AES ciphertext from base64
        aes_key = base64.b64decode(aes_key_b64)            # Decode AES key from base64
        nonce = base64.b64decode(nonce_b64)                # Decode nonce used during AES encryption
        tag = base64.b64decode(tag_b64)                    # Decode AES tag used for message integrity

        aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)  # Initialize AES cipher with key and nonce
        pt = aes_cipher.decrypt_and_verify(ct1, tag).decode()     # Decrypt and verify tag, then decode to string

        return {"decrypted": pt, "success_ct1": True}       # Return successfully decrypted plaintext
    except:
        return {"error_ct1": "❌ Final decryption failed. Invalid AES secret key or CT1."}  # Handle AES decryption failure
