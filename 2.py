import hashlib
import os
from ecdsa import SigningKey, SECP256k1

# Function to hash data using SHA-256
def sha256(data):
    return hashlib.sha256(data).digest()

# Function to generate Schnorr signature
def schnorr_sign(private_key, message):
    if isinstance(message, str):
        message = message.encode()

    # Step 1: Choose a random nonce k
    k = int.from_bytes(os.urandom(32), 'big') % SECP256k1.order

    # Step 2: Compute R = k * G (public commitment)
    R = k * SECP256k1.generator
    R_bytes = R.x().to_bytes(32, 'big')

    # Step 3: Compute e = H(R || P || message), where P is the public key
    public_key = private_key.get_verifying_key()
    e = sha256(R_bytes + public_key.to_string() + message)
    e = int.from_bytes(e, 'big') % SECP256k1.order

    # Step 4: Compute the signature s = k + e * x (mod n)
    s = (k + e * private_key.privkey.secret_multiplier) % SECP256k1.order
    return R_bytes, s

# Function to verify Schnorr signature
def schnorr_verify(public_key, message, R_bytes, s):
    if isinstance(message, str):
        message = message.encode()

    # Step 1: Compute e = H(R || P || message)
    e = sha256(R_bytes + public_key.to_string() + message)
    e = int.from_bytes(e, 'big') % SECP256k1.order

    # Step 2: Compute s * G and e * P
    sG = s * SECP256k1.generator
    eP = e * public_key.pubkey.point

    # Step 3: Compute R' = sG + (-eP)
    R_prime = sG + (-eP)

    # Step 4: Verify if R_prime.x == R_bytes (recomputed R)
    return R_prime.x() == int.from_bytes(R_bytes, 'big')

# Example usage:
if __name__ == "__main__":
    # Step 1: Generate private and public key
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()

    # Step 2: Take user input for the message
    message = input("Enter the message you want to sign: ")

    # Step 3: Sign the user-inputted message
    R_bytes, s = schnorr_sign(private_key, message)

    # Step 4: Verify the signature
    is_valid = schnorr_verify(public_key, message, R_bytes, s)

    # Output results
    print(f"Signature valid: {is_valid}")
    print(f"Signature: (R: {R_bytes.hex()}, s: {s})")
