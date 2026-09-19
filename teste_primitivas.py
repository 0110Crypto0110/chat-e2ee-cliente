import os
import primitivas_rust as pr

# HMAC
key = os.urandom(32)
msg = b"mensagem de teste"
tag = pr.hmac_sha256(key, msg)
assert len(tag) == 32
assert pr.hmac_sha256_verify(key, msg, tag) is True
assert pr.hmac_sha256_verify(key, b"outra", tag) is False
print("HMAC OK")

# HKDF (deriva 64 bytes = 32 AES + 32 HMAC)
okm = pr.hkdf_sha256(os.urandom(32), os.urandom(16), b"canal-v1", 64)
assert len(okm) == 64
print("HKDF OK")

# X25519 (Alice e Bob chegam ao mesmo segredo)
a_priv, b_priv = os.urandom(32), os.urandom(32)
a_pub = pr.x25519_public_from_private(a_priv)
b_pub = pr.x25519_public_from_private(b_priv)
assert pr.x25519_shared(a_priv, b_pub) == pr.x25519_shared(b_priv, a_pub)
print("X25519 OK")

# AES-256-GCM roundtrip
k = os.urandom(32)
n = os.urandom(12)
ct = pr.aes256_encrypt(k, b"ola mundo", n)
assert pr.aes256_decrypt(k, ct, n) == b"ola mundo"
print("AES OK")

print(">>> TODAS AS PRIMITIVAS FUNCIONANDO <<<")