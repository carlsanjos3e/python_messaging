import hashlib

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Generates a simple RSA keypair
def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537

    # Ensure e and phi are coprime
    if gcd(e, phi) != 1:
        raise Exception("e and phi(n) are not coprime. Choose different primes.")

    d = pow(e, -1, phi)
    return (e, n), (d, n)

# Encrypts a message using the public key
def encrypt_message(public_key, message):
    e, n = public_key
    cipher = [str(pow(ord(char), e, n)) for char in message]
    return ','.join(cipher)

# Decrypts a message using the private key
def decrypt_message(private_key, encrypted_message):
    d, n = private_key
    nums = list(map(int, encrypted_message.split(',')))
    return ''.join([chr(pow(num, d, n)) for num in nums])

# Hashes a string using SHA-256 and returns hex digest
def hash_message(message):
    return hashlib.sha256(message.encode()).hexdigest()
