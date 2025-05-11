# crypto_utils.py

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_keypair():
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def encrypt_message(public_key, message):
    e, n = public_key
    return ','.join([str(pow(ord(c), e, n)) for c in message])

def decrypt_message(private_key, ciphertext):
    d, n = private_key
    nums = list(map(int, ciphertext.split(',')))
    return ''.join([chr(pow(num, d, n)) for num in nums])
