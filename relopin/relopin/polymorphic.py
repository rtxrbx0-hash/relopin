"""
polymorphic.py
---------------
هذا هو قلب "المحرك المتعدد الأشكال": لكل build، يقرر عشوائيًا (من seed واحد للبناء):
  - اسم حزمة/كلاس RelopinRuntime (مكان مختلف في كل مرة)
  - ترتيب وعدد الفخاخ (honey functions) وأسماءها
  - أي سلاسل نصية (strings) تُشفَّر ضمن الـ smali المستهدف
  - مقدار/مواقع junk identifiers المُولَّدة

النتيجة: لا بناءان متماثلان بتياً حتى لو كان الـ APK المدخل وقائمة الإعدادات متطابقين تمامًا،
لأن seed مختلف في كل مرة (seed.new_build_seed) يعيد توليد كل هذه القرارات من الصفر.
"""
from __future__ import annotations

import dataclasses
import random
import string

from . import rustcore
from .seed import SplitMix64, derive_bytes, derive_subseed

_PKG_WORDS = ["core", "sys", "util", "base", "rt", "svc", "mod", "lib", "eng", "io"]


def _rand_package(rng: SplitMix64) -> str:
    depth = 2 + rng.randbelow(2)  # 2..3 مستويات
    parts = []
    for _ in range(depth):
        word = rng.choice(_PKG_WORDS)
        suffix = "".join(rng.choice(string.ascii_lowercase) for _ in range(3))
        parts.append(f"{word}{suffix}")
    return "com/" + "/".join(parts)


def _rand_classname(rng: SplitMix64) -> str:
    letters = string.ascii_uppercase
    return rng.choice(letters) + "".join(
        rng.choice(string.ascii_lowercase) for _ in range(5 + rng.randbelow(5))
    )


@dataclasses.dataclass
class BuildPlan:
    master_seed: int
    runtime_package: str       # مثال: com/svcxyz/engabc
    runtime_class: str         # مثال: Qxrmpt
    build_seed_bytes: bytes    # يُضمَّن في RelopinRuntime.smali كـ BUILD_SEED
    device_salt_bytes: bytes   # يُضمَّن في RelopinRuntime.smali كـ DEVICE_SALT (إصلاح #1: نفس
                                # القيمة بالضبط تُستخدم هنا وهناك، فيتطابق التشفير وفك التشفير دائمًا)
    naming_seed: int
    honey_seed: int
    string_enc_seed: int


def build_plan(master_seed: int, deterministic: bool = False) -> BuildPlan:
    """
    إصلاح ثغرة في تعاقد `--seed`: الكود السابق كان يولّد build_seed_bytes/device_salt_bytes
    (مادة المفتاح الفعلية المُضمَّنة في RelopinRuntime.smali والمستخدمة في التشفير) دائمًا عبر
    `random.SystemRandom()`، بغض النظر تمامًا عن master_seed — حتى لو مرّر المستخدم
    `--seed 123456789`. لكن CLI/README يوثّقان --seed صراحة بأنه "لإعادة إنتاج بناء محدد
    أثناء الـ debugging"، وهذا كان وعدًا كاذبًا عمليًا: نفس --seed كان يُعطي نفس اسم
    الحزمة/الكلاس ونفس اختيار السلاسل/الفخاخ، لكن **محتوى تشفير مختلف في كل مرة** (seed/salt
    مختلفان، فنواتج ciphertext مختلفة) — غير قابل لإعادة الإنتاج فعليًا رغم التوثيق.

    الإصلاح: `deterministic=True` (يُمرَّره cli.py فقط حين يُحدِّد المستخدم --seed صراحة) يشتق
    seed/salt حتميًا من master_seed عبر seed.derive_bytes (تمديد SHA-256) — بناء قابل لإعادة
    إنتاج حرفي الآن فعلاً. المسار الافتراضي (بدون --seed) يبقى كما كان: CSPRNG حقيقي عبر
    SystemRandom لكل build، يحافظ على كامل الإنتروبي (256-بت مستقلة) وعلى ميزة "لا بناءان
    متماثلان بتيًا أبدًا" الموثَّقة في README — لا تراجع أمني في المسار الافتراضي.
    """
    naming_seed = derive_subseed(master_seed, "naming")
    honey_seed = derive_subseed(master_seed, "honey")
    string_enc_seed = derive_subseed(master_seed, "strings")

    rng = SplitMix64(naming_seed)
    pkg = _rand_package(rng)
    cls = _rand_classname(rng)

    if deterministic:
        build_seed_bytes = derive_bytes(master_seed, "build_seed", 16)
        device_salt_bytes = derive_bytes(master_seed, "device_salt", 16)
    else:
        # 16 بايت عشوائية حقيقية (CSPRNG عبر random.SystemRandom) — هذه هي "البذرة" المضمَّنة
        # فعليًا داخل الـ APK المبني ويُشتق منها المفتاح وقت التشغيل مع ملح الجهاز.
        sysrand = random.SystemRandom()
        build_seed_bytes = bytes(sysrand.randrange(256) for _ in range(16))
        device_salt_bytes = bytes(sysrand.randrange(256) for _ in range(16))

    return BuildPlan(
        master_seed=master_seed,
        runtime_package=pkg,
        runtime_class=cls,
        build_seed_bytes=build_seed_bytes,
        device_salt_bytes=device_salt_bytes,
        naming_seed=naming_seed,
        honey_seed=honey_seed,
        string_enc_seed=string_enc_seed,
    )


def smali_byte_array_literal(data: bytes, out_register: str = "v0", label: str = "build_seed_data") -> str:
    """
    يولّد تعليمات smali لبناء مصفوفة بايت ثابتة (BUILD_SEED أو DEVICE_SALT داخل <clinit>).
    مصفوفات smali الثابتة تُبنى بتعليمات fill-array-data مرتبطة بجدول بيانات.

    `label` **يجب** أن يكون فريدًا داخل نفس الـ method لو استُدعيت هذه الدالة أكثر من مرة
    (مثلاً مرة لـ BUILD_SEED ومرة لـ DEVICE_SALT داخل نفس <clinit>) — وإلا يحدث تصادم تسميات.
    """
    n = len(data)
    lines = [f"    const/16 {out_register}, 0x{n:x}"]
    lines.append(f"    new-array {out_register}, {out_register}, [B")
    lines.append(f"    fill-array-data {out_register}, :{label}")
    tail = [
        f"    goto :after_{label}",
        f"    :{label}",
        "    .array-data 1",
    ]
    for b in data:
        signed = b if b < 128 else b - 256
        tail.append(f"        {signed}t")
    tail.append("    .end array-data")
    tail.append(f"    :after_{label}")
    return "\n".join(lines + tail)


def encrypt_string_for_device(build_seed_bytes: bytes, device_salt_bytes: bytes, plaintext: str) -> bytes:
    """
    يشفّر نصًا واحدًا بنفس الخوارزمية المطابقة في RelopinRuntime.smali (derive-key-simple ثم
    xor-stream-simple). دالة مساعدة مريحة لسكربتات/اختبارات فردية (وحدة واحدة فقط من النصوص)؛
    smali_injector.inject_string_encryption يستخدم rustcore.batch_encrypt_simple مباشرة
    بدلاً منها عند معالجة APK كامل، لأنه أسرع بمرّات (استدعاء subprocess واحد لا واحد لكل نص
    — إصلاح الثغرة #9).

    (إصلاح الثغرة #1): `build_seed_bytes` و`device_salt_bytes` يجب أن يكونا **نفس القيمتين
    بالضبط** المضمَّنتين في RelopinRuntime.smali (عادة plan.build_seed_bytes/device_salt_bytes
    من BuildPlan واحد) — DEVICE_SALT الآن حقل ثابت يُضمَّن وقت البناء، وليس محسوبًا من
    Build.* على الجهاز كما كان سابقًا (كان هذا هو سبب الفشل الدائم في فك التشفير في v0.1).
    """
    key = rustcore.derive_key_simple(build_seed_bytes, device_salt_bytes)
    return rustcore.xor_stream_simple(key, plaintext.encode("utf-8"))
