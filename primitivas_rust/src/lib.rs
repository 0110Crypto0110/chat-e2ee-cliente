use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------

#[pyfunction]
fn aes256_encrypt(
    py: Python<'_>,
    key: &[u8],
    plaintext: &[u8],
    nonce_bytes: &[u8],
) -> PyResult<Py<PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err(
            "A chave AES-256 deve ter exatamente 32 bytes.",
        ));
    }
    if nonce_bytes.len() != 12 {
        return Err(PyValueError::new_err(
            "O nonce deve ter exatamente 12 bytes.",
        ));
    }
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| PyValueError::new_err(format!("Falha ao cifrar: {e}")))?;
    Ok(PyBytes::new(py, &ct).into())
}

#[pyfunction]
fn aes256_decrypt(
    py: Python<'_>,
    key: &[u8],
    ciphertext: &[u8],
    nonce_bytes: &[u8],
) -> PyResult<Py<PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err(
            "A chave AES-256 deve ter exatamente 32 bytes.",
        ));
    }
    if nonce_bytes.len() != 12 {
        return Err(PyValueError::new_err(
            "O nonce deve ter exatamente 12 bytes.",
        ));
    }
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let pt = cipher.decrypt(nonce, ciphertext).map_err(|e| {
        PyValueError::new_err(format!(
            "Falha ao decifrar (chave errada ou dado corrompido): {e}"
        ))
    })?;
    Ok(PyBytes::new(py, &pt).into())
}

// ---------------------------------------------------------------------
// HMAC-SHA-256
// ---------------------------------------------------------------------

#[pyfunction]
fn hmac_sha256(
    py: Python<'_>,
    key: &[u8],
    message: &[u8],
) -> PyResult<Py<PyBytes>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| PyValueError::new_err(format!("Chave HMAC inválida: {e}")))?;
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    Ok(PyBytes::new(py, &tag).into())
}

#[pyfunction]
fn hmac_sha256_verify(
    key: &[u8],
    message: &[u8],
    expected_tag: &[u8],
) -> PyResult<bool> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| PyValueError::new_err(format!("Chave HMAC inválida: {e}")))?;
    mac.update(message);
    Ok(mac.verify_slice(expected_tag).is_ok())
}

// ---------------------------------------------------------------------
// HKDF-SHA-256
// ---------------------------------------------------------------------

#[pyfunction]
fn hkdf_sha256(
    py: Python<'_>,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> PyResult<Py<PyBytes>> {
    if length == 0 || length > 255 * 32 {
        return Err(PyValueError::new_err(
            "Comprimento HKDF inválido (1..=8160 bytes).",
        ));
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|e| PyValueError::new_err(format!("Falha no HKDF: {e}")))?;
    Ok(PyBytes::new(py, &okm).into())
}

// ---------------------------------------------------------------------
// X25519 (Diffie-Hellman)
// ---------------------------------------------------------------------

#[pyfunction]
fn x25519_public_from_private(
    py: Python<'_>,
    private_bytes: &[u8],
) -> PyResult<Py<PyBytes>> {
    if private_bytes.len() != 32 {
        return Err(PyValueError::new_err(
            "Chave privada X25519 deve ter 32 bytes.",
        ));
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(private_bytes);
    let secret = StaticSecret::from(sk);
    let public = PublicKey::from(&secret);
    Ok(PyBytes::new(py, public.as_bytes()).into())
}

#[pyfunction]
fn x25519_shared(
    py: Python<'_>,
    private_bytes: &[u8],
    peer_public_bytes: &[u8],
) -> PyResult<Py<PyBytes>> {
    if private_bytes.len() != 32 {
        return Err(PyValueError::new_err(
            "Chave privada X25519 deve ter 32 bytes.",
        ));
    }
    if peer_public_bytes.len() != 32 {
        return Err(PyValueError::new_err(
            "Chave pública X25519 deve ter 32 bytes.",
        ));
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(private_bytes);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(peer_public_bytes);

    let secret = StaticSecret::from(sk);
    let peer_public = PublicKey::from(pk);
    let shared = secret.diffie_hellman(&peer_public);
    Ok(PyBytes::new(py, shared.as_bytes()).into())
}

// ---------------------------------------------------------------------
// Registro do módulo (PyO3 0.20)
// ---------------------------------------------------------------------

#[pymodule]
fn primitivas_rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(aes256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(hmac_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(hmac_sha256_verify, m)?)?;
    m.add_function(wrap_pyfunction!(hkdf_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_public_from_private, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_shared, m)?)?;
    Ok(())
}