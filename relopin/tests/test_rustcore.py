"""
اختبارات آلية (إصلاح الثغرة #8: لم تكن هناك أي اختبارات قابلة للتشغيل — كل "التحقق" كان
موصوفًا نصيًا في README فقط). شغّل: `pytest tests/ -v` من جذر المشروع (بعد `cargo build
--release` في rust_core/).
"""
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from relopin import rustcore  # noqa: E402


def test_sha256_official_vector():
    assert rustcore.sha256(b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_empty():
    assert rustcore.sha256(b"").hex() == hashlib.sha256(b"").hexdigest()


def _python_reference_cipher(seed: bytes, salt: bytes, plaintext: bytes) -> bytes:
    """نفس الخوارزمية المطبَّقة في RelopinRuntime.smali عبر MessageDigest الحقيقي."""
    key = hashlib.sha256(seed + salt).digest()
    out = bytearray()
    counter = 0
    block = hashlib.sha256(key + str(counter).encode()).digest()
    pos = 0
    for b in plaintext:
        if pos == len(block):
            counter += 1
            block = hashlib.sha256(key + str(counter).encode()).digest()
            pos = 0
        out.append(b ^ block[pos])
        pos += 1
    return bytes(out)


@pytest.mark.parametrize(
    "seed,salt,plaintext",
    [
        (b"\xde\xad\xbe\xef", b"\x00\x11\x22\x33", b"hello world"),
        (b"", b"", b""),
        (bytes(range(16)), bytes(range(16, 32)), "اختبار نص عربي 🔐".encode("utf-8")),
        (bytes(16), bytes(16), b"x" * 500),  # أطول من بلوك SHA-256 واحد (32 بايت)
    ],
)
def test_derive_key_and_cipher_match_python_reference(seed, salt, plaintext):
    key = rustcore.derive_key_simple(seed, salt)
    assert key == hashlib.sha256(seed + salt).digest()

    ciphertext = rustcore.xor_stream_simple(key, plaintext)
    assert ciphertext == _python_reference_cipher(seed, salt, plaintext)

    # XOR متماثل: فك التشفير = نفس الدالة مرة ثانية
    decrypted = rustcore.xor_stream_simple(key, ciphertext)
    assert decrypted == plaintext


def test_batch_encrypt_matches_individual_calls():
    seed = b"\x01\x02\x03\x04"
    salt = b"\xaa\xbb\xcc\xdd"
    plaintexts = [b"first string", b"second one", "عربي أيضًا".encode("utf-8"), b""]

    key = rustcore.derive_key_simple(seed, salt)
    individual = [rustcore.xor_stream_simple(key, p) for p in plaintexts if p]  # نتجاهل الفارغ (batch يتجاهل الأسطر الفارغة)

    batch = rustcore.batch_encrypt_simple(seed, salt, [p for p in plaintexts if p])
    assert batch == individual


def test_batch_encrypt_empty_list():
    assert rustcore.batch_encrypt_simple(b"\x00", b"\x00", []) == []


def test_encrypt_string_for_device_convenience_wrapper():
    from relopin.polymorphic import encrypt_string_for_device

    seed = bytes(range(16))
    salt = bytes(range(16, 32))
    ct = encrypt_string_for_device(seed, salt, "hello")
    pt = rustcore.xor_stream_simple(rustcore.derive_key_simple(seed, salt), ct)
    assert pt == b"hello"


def test_invalid_hex_raises_not_silently_zero():
    """إصلاح الثغرة #7: hex غير صالح يجب أن يرفع خطأ، لا يتحوّل صمتًا إلى صفر."""
    import subprocess

    bin_path = rustcore._find_bin()
    proc = subprocess.run([bin_path, "sha256", "zz"], capture_output=True, text=True)
    assert proc.returncode != 0
    assert "خطأ" in proc.stderr or "error" in proc.stderr.lower()
