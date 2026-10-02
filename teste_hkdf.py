import os
import primitivas_rust as prim
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

ikm = os.urandom(32)
salt = os.urandom(16)
info = b"canal-cliente-servidor"

# --- Rust ---
okm_rust = bytes(prim.hkdf_sha256(ikm, salt, info, 64))

# --- Python ---
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=64,
    salt=salt,
    info=info,
)
okm_py = hkdf.derive(ikm)

print("okm_rust:", okm_rust.hex())
print("okm_py  :", okm_py.hex())
print("IGUAIS:", okm_rust == okm_py)