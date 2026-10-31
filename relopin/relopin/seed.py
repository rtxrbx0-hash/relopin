"""
seed.py
--------
كل بناء (build) يحصل على seed عشوائي 64-بت واحد (أو يفرضه المستخدم لإعادة إنتاج بناء معيّن
لأغراض debug). من هذا الـ seed الرئيسي نشتق seeds فرعية مستقلة لكل مرحلة (تسمية، تشفير نصوص،
حقن junk، اختيار فخاخ) بحيث تغيير مرحلة واحدة لا يكسر توافق بقية المراحل، وبحيث لا يتكرر
نفس التحويل بين بناءين حتى لو فعّلا نفس الميزات على نفس الـ APK.

لا اعتماديات خارجية: نستخدم os.urandom + hashlib فقط (مكتبة قياسية).
"""
from __future__ import annotations

import hashlib
import os
import struct


def new_build_seed() -> int:
    """seed عشوائي حقيقي (CSPRNG) لكل build، 64-bit."""
    return struct.unpack(">Q", os.urandom(8))[0]


def derive_subseed(master_seed: int, label: str) -> int:
    """
    اشتقاق seed فرعي حتمي من master_seed + تسمية المرحلة (label).
    نفس master_seed + نفس label => نفس subseed دائمًا (حتمية داخل البناء نفسه)،
    لكن subseeds مختلف المراحل مستقلة إحصائيًا لأنها مبنية على هاش مختلف المدخل.
    """
    h = hashlib.sha256(f"{master_seed}:{label}".encode()).digest()
    return struct.unpack(">Q", h[:8])[0]


def derive_bytes(master_seed: int, label: str, n: int) -> bytes:
    """
    اشتقاق n بايت حتمية من master_seed + label (تمديد SHA-256 بأسلوب counter-mode، HKDF
    مبسّط). تُستخدم **فقط** حين يُمرَّر `--seed` صراحة (وضع إعادة-إنتاج-بناء للـ debugging) —
    راجع التعليق في polymorphic.build_plan لشرح سبب وجود هذه الدالة أصلاً.
    """
    out = bytearray()
    counter = 0
    while len(out) < n:
        out.extend(hashlib.sha256(f"{master_seed}:{label}:{counter}".encode()).digest())
        counter += 1
    return bytes(out[:n])


class SplitMix64:
    """
    مولّد أرقام شبه عشوائي حتمي (PRNG) بسيط وسريع، بذرة 64-bit.
    ليس للاستخدام التشفيري — فقط لاتخاذ قرارات التحويل (أي اسم؟ أي فخ؟ أي ترتيب junk؟)
    بشكل قابل لإعادة الإنتاج من نفس الـ seed.
    """

    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next_u64(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        z = z ^ (z >> 31)
        return z

    def randbelow(self, n: int) -> int:
        if n <= 0:
            return 0
        return self.next_u64() % n

    def choice(self, seq):
        return seq[self.randbelow(len(seq))]

    def shuffle(self, seq: list) -> list:
        a = list(seq)
        for i in range(len(a) - 1, 0, -1):
            j = self.randbelow(i + 1)
            a[i], a[j] = a[j], a[i]
        return a
