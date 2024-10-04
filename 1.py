from ecies.utils import generate_key
from ecies import encrypt, decrypt

# Generate the key pair (private and public key)
private_key = generate_key()
public_key = private_key.public_key

# Take user input for the message
message = input("Enter the message to encrypt: ").encode('utf-8')

# Encrypt the message using the public key
ciphertext = encrypt(public_key.format(True), message)
print('\nEncrypted message:', ciphertext)

# Decrypt the message using the private key
decrypted_message = decrypt(private_key.to_hex(), ciphertext)
print("\nDecrypted message:", decrypted_message.decode('utf-8'))