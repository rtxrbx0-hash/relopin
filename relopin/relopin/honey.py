"""
honey.py
--------
فخاخ العسل (Honey Functions): دوال مُحقَنة تحمل "سرًا" زائفًا (مفتاح API وهمي، رابط سيرفر
وهمي، توكن وهمي...) يختاره المطوّر بنفسه عبر ملف إعداد JSON/YAML بسيط (انظر honeytraps.example.json).
الفكرة: محلل آلي أو يدوي يفكك الـ APK، يجد الدالة، "يسرق" القيمة المرتجعة، يحاول استخدامها
(عادة بإرسالها لسيرفر ليتأكد أنها صالحة) — وعندها فقط (عند استخدام القيمة الزائفة فعليًا على
سيرفر المطوّر) يعرف المطوّر أن أحدًا يحلل تطبيقه، لأن القيمة لا قيمة حقيقية لها لأي غرض آخر.

relopin نفسه لا "يتصل بأي سيرفر" ولا يقرر منطق التنبيه — هو فقط يحقن الدالة التي تُرجع القيمة
التي يحددها المطوّر، وأي رصد/تنبيه خارج هذا النطاق بالكامل (أمر المطوّر، على سيرفره هو).
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from .seed import SplitMix64


@dataclasses.dataclass
class HoneyTrap:
    name_hint: str       # اسم منطقي يستخدمه المطور للتعرف عليه في التقرير (لا يظهر في الـ APK)
    fake_value: str       # القيمة الزائفة التي تُرجعها الدالة (يحددها المطور بالكامل)
    return_type: str = "string"  # حاليًا ندعم string فقط في المولّد الافتراضي


def load_honey_config(path: str | Path) -> list[HoneyTrap]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    traps = []
    for item in data.get("traps", []):
        traps.append(
            HoneyTrap(
                name_hint=item["name_hint"],
                fake_value=item["fake_value"],
                return_type=item.get("return_type", "string"),
            )
        )
    if not traps:
        raise ValueError("honeytraps config فارغ — أضف trap واحدًا على الأقل في 'traps'.")
    return traps


_METHOD_NAME_WORDS = [
    "getConfig", "fetchToken", "loadKey", "readCache", "initSecure",
    "getSessionKey", "resolveEndpoint", "getLicenseSeed", "loadCredential",
]


def plan_injection_names(traps: list[HoneyTrap], seed: int) -> list[tuple[HoneyTrap, str]]:
    """يعطي كل فخ اسم دالة smali عشوائي (يتغيّر كل بناء بسبب seed)."""
    rng = SplitMix64(seed)
    out = []
    for trap in traps:
        base = rng.choice(_METHOD_NAME_WORDS)
        suffix = "".join(rng.choice("0123456789abcdef") for _ in range(4))
        out.append((trap, f"{base}_{suffix}"))
    return out


_SUPPORTED_RETURN_TYPES = {"string", "int"}


def smali_trap_method(method_name: str, fake_value: str, return_type: str = "string") -> str:
    """
    يولّد smali method كاملة static تُرجع fake_value. بسيطة عمدًا: الهدف أن تبدو كدالة
    إعداد/تحميل مفتاح طبيعية بالنسبة لمحلل يقرأ القيمة، لا تنفيذ منطق إضافي يكشفها.

    (إصلاح الثغرة #10): `return_type` كان حقلاً في HoneyTrap بلا أي تأثير فعلي — الآن يُستخدم
    فعليًا لتوليد توقيع/تعليمات smali مختلفة حسب النوع. حاليًا مدعوم "string" و"int"؛ أي قيمة
    أخرى تُرفَض بخطأ واضح بدل تجاهلها صمتًا.
    """
    if return_type not in _SUPPORTED_RETURN_TYPES:
        raise ValueError(
            f"return_type={return_type!r} غير مدعوم حاليًا. المدعوم: {sorted(_SUPPORTED_RETURN_TYPES)}"
        )

    if return_type == "string":
        escaped = fake_value.replace("\\", "\\\\").replace('"', '\\"')
        return (
            f".method public static {method_name}()Ljava/lang/String;\n"
            f"    .registers 1\n"
            f'    const-string v0, "{escaped}"\n'
            f"    return-object v0\n"
            f".end method\n"
        )

    # return_type == "int"
    try:
        int_value = int(fake_value, 0)  # يدعم "123" أو "0x7b" إلخ
    except ValueError as exc:
        raise ValueError(
            f'fake_value={fake_value!r} غير قابل للتحويل إلى int (return_type="int")'
        ) from exc
    return (
        f".method public static {method_name}()I\n"
        f"    .registers 1\n"
        f"    const v0, 0x{int_value & 0xFFFFFFFF:x}\n"
        f"    return v0\n"
        f".end method\n"
    )
