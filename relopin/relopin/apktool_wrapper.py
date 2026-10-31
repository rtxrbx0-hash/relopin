"""
apktool_wrapper.py
-------------------
relopin لا يعيد تطبيق محرك dex/smali (baksmali/smali/dx/d8) من الصفر — هذا مذكور صراحة في
المتطلبات كاستثناء مسموح. هذا الملف فقط يستدعي apktool (أو أي أداة متوافقة تضعها عبر
--apktool-cmd) لفك/إعادة تجميع الـ APK، ويترك كل التعديلات الفعلية على ملفات smali
لبقية relopin (smali_injector.py).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class ApktoolError(RuntimeError):
    pass


def _resolve_apktool(cmd: str | None) -> str:
    if cmd:
        return cmd
    found = shutil.which("apktool")
    if found:
        return found
    raise ApktoolError(
        "apktool غير موجود في PATH. ثبّته أو مرّر مساره عبر --apktool-cmd.\n"
        "(هذا هو الاعتماد الخارجي الوحيد المسموح به في relopin، حسب المتطلبات.)"
    )


def decode(apk_path: str, out_dir: str, apktool_cmd: str | None = None) -> None:
    exe = _resolve_apktool(apktool_cmd)
    out = Path(out_dir)
    if out.exists():
        shutil.rmtree(out)
    proc = subprocess.run(
        [exe, "d", "-f", "-o", str(out), apk_path],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise ApktoolError(f"apktool decode فشل:\n{proc.stdout}\n{proc.stderr}")


def build(decoded_dir: str, out_apk: str, apktool_cmd: str | None = None) -> None:
    exe = _resolve_apktool(apktool_cmd)
    proc = subprocess.run(
        [exe, "b", decoded_dir, "-o", out_apk],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise ApktoolError(f"apktool build فشل:\n{proc.stdout}\n{proc.stderr}")
