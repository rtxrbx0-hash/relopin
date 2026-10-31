"""
rustcore.py
-----------
غلاف رفيع يستدعي ثنائي relopin-core (Rust) عبر subprocess. لا PyO3 ولا أي ربط FFI معقّد
عمدًا — subprocess + hex/stdin/stdout يبقي الحدود بين اللغتين بسيطة وقابلة للتدقيق (تقدر
تشغّل relopin-core بمفردها وتتحقق من كل مخرج يدويًا).

(إصلاح الثغرة #10): أُزيلت derive_key/xor_crypt (مسار HKDF العام) لأنها لم تكن مُستخدمة في أي
مكان فعلي بالأداة — كود ميت. البقية فقط: المسار "simple" المُستخدم فعليًا في smali_injector.py،
زائد batch_encrypt_simple الجديدة (إصلاح الثغرة #9).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

_BIN_CANDIDATES = [
    Path(__file__).resolve().parent.parent / "rust_core" / "target" / "release" / "relopin-core",
    Path(__file__).resolve().parent.parent / "rust_core" / "target" / "debug" / "relopin-core",
]


class RustCoreNotBuilt(RuntimeError):
    pass


def _find_bin() -> str:
    for p in _BIN_CANDIDATES:
        if p.exists():
            return str(p)
    found = shutil.which("relopin-core")
    if found:
        return found
    raise RustCoreNotBuilt(
        "relopin-core لم يُبنَ بعد. شغّل:\n"
        "  cd rust_core && cargo build --release"
    )


def _run(*args: str) -> str:
    bin_path = _find_bin()
    proc = subprocess.run([bin_path, *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"relopin-core فشل: {proc.stderr.strip()}")
    return proc.stdout.strip()


def derive_key_simple(build_seed: bytes, device_salt: bytes) -> bytes:
    out = _run("derive-key-simple", build_seed.hex(), device_salt.hex())
    return bytes.fromhex(out)


def xor_stream_simple(key: bytes, data: bytes) -> bytes:
    out = _run("xor-stream-simple", key.hex(), data.hex())
    return bytes.fromhex(out)


def batch_encrypt_simple(build_seed: bytes, device_salt: bytes, plaintexts: list[bytes]) -> list[bytes]:
    """
    يشفّر عدة نصوص في استدعاء subprocess **واحد** بدل واحد لكل نص (إصلاح الثغرة #9: كان
    بناء APK متوسط يستلزم عشرات الآلاف من استدعاءات subprocess منفصلة، كل واحد بتكلفة fork/exec
    كاملة — بطء شديد). الآن: عملية واحدة، كل النصوص عبر stdin، كل النواتج عبر stdout.
    """
    if not plaintexts:
        return []
    bin_path = _find_bin()
    stdin_data = "\n".join(p.hex() for p in plaintexts) + "\n"
    proc = subprocess.run(
        [bin_path, "batch-encrypt-simple", build_seed.hex(), device_salt.hex()],
        input=stdin_data,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"relopin-core batch-encrypt-simple فشل: {proc.stderr.strip()}")
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if len(lines) != len(plaintexts):
        raise RuntimeError(
            f"relopin-core batch-encrypt-simple أرجع {len(lines)} سطرًا، متوقَّع {len(plaintexts)}"
        )
    return [bytes.fromhex(line) for line in lines]


def gen_junk_names(seed: int, count: int) -> list[str]:
    out = _run("gen-junk", str(seed), str(count))
    return [line for line in out.splitlines() if line]


def sha256(data: bytes) -> bytes:
    out = _run("sha256", data.hex())
    return bytes.fromhex(out)
