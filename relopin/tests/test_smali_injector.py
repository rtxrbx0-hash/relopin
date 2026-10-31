import hashlib
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from relopin.polymorphic import build_plan  # noqa: E402
from relopin.seed import new_build_seed  # noqa: E402
from relopin import smali_injector as si  # noqa: E402


MULTI_METHOD_SMALI = """.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;
.source "MainActivity.java"

.method public onCreate(Landroid/os/Bundle;)V
    .locals 3
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    const-string v0, "https://api.supersecretbackend.com/v1/auth"

    const-string v1, "user_api_key_abcdef123456"

    invoke-static {v0}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2

    return-void
.end method

.method public noSecrets(I)V
    .locals 2
    const/4 v0, 0x0
    const-string v1, "ok"
    return-void
.end method

.method public withAnnotationAndJumbo()V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "const-string v99, \\"not a real instruction, should be ignored\\""
        }
    .end annotation
    const-string/jumbo v0, "a reasonably long secret token value here"
    const-string v1, "short"
    return-void
.end method

.method private static oldStyleRegisters(I)V
    .registers 3
    const-string v0, "this method uses .registers and must be left untouched entirely"
    return-void
.end method
"""


@pytest.fixture()
def work_dir(tmp_path):
    smali_dir = tmp_path / "smali" / "com" / "example" / "app"
    smali_dir.mkdir(parents=True)
    (smali_dir / "MainActivity.smali").write_text(MULTI_METHOD_SMALI, encoding="utf-8")
    return tmp_path


def _decrypt_reference(seed_bytes: bytes, salt_bytes: bytes, ct: bytes) -> str:
    key = hashlib.sha256(seed_bytes + salt_bytes).digest()
    out = bytearray()
    counter = 0
    block = hashlib.sha256(key + str(counter).encode()).digest()
    pos = 0
    for b in ct:
        if pos == len(block):
            counter += 1
            block = hashlib.sha256(key + str(counter).encode()).digest()
            pos = 0
        out.append(b ^ block[pos])
        pos += 1
    return bytes(out).decode("utf-8")


def _extract_array(text: str, label_with_colon: str) -> bytes:
    """label_with_colon مثال: ':device_salt_data' أو ':relopin_arr_7_0'."""
    m = re.search(
        re.escape(label_with_colon) + r"\n    \.array-data 1\n((?:        -?\d+t\n)+)    \.end array-data",
        text,
    )
    assert m, f"label {label_with_colon} not found"
    nums = [int(x.strip()[:-1]) for x in m.group(1).strip().splitlines()]
    return bytes((n + 256) % 256 for n in nums)


def test_full_injection_roundtrip(work_dir):
    honey_cfg = Path(__file__).resolve().parent.parent / "honeytraps.example.json"
    report = si.run_build(
        apk_decoded_dir=str(work_dir),
        master_seed=new_build_seed(),
        honey_cfg_path=str(honey_cfg),
        string_enc_probability_pct=100,  # إجبار التشفير على كل مرشّح مؤهَّل
    )

    assert report.honey_injected  # فخاخ العسل حُقنت

    main_activity = (work_dir / "smali/com/example/app/MainActivity.smali").read_text(encoding="utf-8")
    runtime_file = work_dir / "smali" / report.plan.runtime_package / f"{report.plan.runtime_class}.smali"
    runtime_text = runtime_file.read_text(encoding="utf-8")

    seed_bytes = report.plan.build_seed_bytes
    salt_bytes = report.plan.device_salt_bytes

    # --- إصلاح #1: تأكد أن الملح المضمَّن في RelopinRuntime.smali يطابق فعليًا ما استُخدم
    #     في التشفير (وليس قيمة مختلفة كما كان في v0.1) ---
    embedded_salt = _extract_array(runtime_text, ":device_salt_data")
    assert embedded_salt == salt_bytes
    embedded_seed = _extract_array(runtime_text, ":build_seed_data")
    assert embedded_seed == seed_bytes

    # --- onCreate: السلسلتان يجب أن تكونا مشفَّرتين وتفكّا بشكل صحيح ---
    # نجد كل التسميات ونفكّ كلاً منها على حدة بدل افتراض اسم ثابت:
    labels = re.findall(r":(relopin_arr_\d+_\d+)\n    \.array-data", main_activity)
    assert len(labels) >= 2  # على الأقل السلسلتان الطويلتان في onCreate

    decrypted_texts = set()
    for label in labels:
        ct = _extract_array(main_activity, f":{label}")
        try:
            decrypted_texts.add(_decrypt_reference(seed_bytes, salt_bytes, ct))
        except UnicodeDecodeError:
            pytest.fail(f"فك تشفير {label} أعطى بايتات غير صالحة — تطابق التشفير/فك التشفير مكسور")

    assert "https://api.supersecretbackend.com/v1/auth" in decrypted_texts
    assert "user_api_key_abcdef123456" in decrypted_texts
    assert "a reasonably long secret token value here" in decrypted_texts  # jumbo دُعم (#5)

    # --- إصلاح #3: method بلا أي سلسلة مؤهَّلة (noSecrets) يجب ألا يتأثر إطلاقًا ---
    assert ".locals 2\n    const/4 v0, 0x0\n    const-string v1, \"ok\"" in main_activity

    # --- الدالة بصيغة .registers يجب أن تبقى كما هي 100% (لم تُلمَس) ---
    assert 'const-string v0, "this method uses .registers and must be left untouched entirely"' in main_activity

    # --- الفخّ المزيّف المخفي داخل .annotation لا يجب أن يُعامَل كسلسلة حقيقية (#5) ---
    assert "not a real instruction" in main_activity  # ما زال موجودًا كنص annotation خام، لم يُشفَّر


def test_state_does_not_leak_between_methods(work_dir):
    """إصلاح #3: تشغيل بـ probability=0 (لا تشفير إطلاقًا) يجب ألا يغيّر الملف على الإطلاق
    باستثناء كتابة RelopinRuntime نفسه (لا شيء يُحقن في الملف المستهدف)."""
    honey_cfg = Path(__file__).resolve().parent.parent / "honeytraps.example.json"
    original = (work_dir / "smali/com/example/app/MainActivity.smali").read_text(encoding="utf-8")

    si.run_build(
        apk_decoded_dir=str(work_dir),
        master_seed=12345,
        honey_cfg_path=str(honey_cfg),
        string_enc_probability_pct=0,
    )

    after = (work_dir / "smali/com/example/app/MainActivity.smali").read_text(encoding="utf-8")
    assert after.strip() == original.strip()


def test_unescape_does_not_corrupt_non_ascii_with_escapes():
    """إصلاح حرج: unicode_escape القديم كان يُفسد أي نص غير-ASCII يحوي أيضًا أي escape.
    هنا نحقن سلسلة عربية تحوي backslash حقيقي داخل method block ونتأكد أن النص الذي يُشفَّر
    فعليًا (ويُفكّ لاحقًا وقت التشغيل) يطابق الأصل حرفيًا، لا mojibake."""
    smali = (
        '.class public Lcom/example/app/Arabic;\n'
        '.super Ljava/lang/Object;\n'
        '.method public static m()V\n'
        '    .locals 1\n'
        '    const-string v0, "\\u0645\\u0631\\u062d\\u0628\\u0627\\n\\u0643\\u064a\\u0641"\n'
        '    return-void\n'
        '.end method\n'
    )
    from relopin.smali_injector import _unescape, CONST_STRING_RE

    m = CONST_STRING_RE.match(smali.splitlines()[4])
    assert m
    literal = m.group(4)
    plaintext = _unescape(literal)
    # النص العربي "مرحبا" + سطر جديد + "كيف" يجب أن يخرج سليمًا بالضبط، لا بايتات مُفسَدة
    assert plaintext == "مرحبا\nكيف"


def test_register_budget_prevents_overflow_past_v15(tmp_path):
    """إصلاح ثغرة فيض السجلات: دالة قريبة من حد 16 سجلًا (locals + بارامترات) يجب ألا يُحقَن
    فيها أكثر مما يبقيها ضمن v0..v15 — وإلا يفشل apktool b على تعليمات 4-بت (invoke القصيرة،
    move، إلخ)."""
    # .locals 14 + static + بلا بارامترات => 14 سجل موجود، البقية المتاحة = 2 فقط
    smali_dir = tmp_path / "smali" / "com" / "example" / "app"
    smali_dir.mkdir(parents=True)
    smali = (
        '.class public Lcom/example/app/Tight;\n'
        '.super Ljava/lang/Object;\n'
        '.method public static m()V\n'
        '    .locals 14\n'
        '    const-string v0, "first secret string value"\n'
        '    const-string v1, "second secret string value"\n'
        '    const-string v2, "third secret string value"\n'
        '    const-string v3, "fourth secret string value"\n'
        '    return-void\n'
        '.end method\n'
    )
    (smali_dir / "Tight.smali").write_text(smali, encoding="utf-8")

    honey_cfg = Path(__file__).resolve().parent.parent / "honeytraps.example.json"
    report = si.run_build(
        apk_decoded_dir=str(tmp_path),
        master_seed=42,
        honey_cfg_path=str(honey_cfg),
        string_enc_probability_pct=100,
    )
    text = (smali_dir / "Tight.smali").read_text(encoding="utf-8")

    m = re.search(r"\.locals (\d+)", text)
    assert m
    new_locals = int(m.group(1))
    assert new_locals <= 16  # لا يتجاوز الحد الآمن إطلاقًا

    # أقصى سجل صريح vN بالملف بأكمله يجب ألا يتجاوز 15
    max_v = max(int(n) for n in re.findall(r"\bv(\d+)\b", text))
    assert max_v <= 15

    # على الأكثر سلسلتان (14+2=16) أُشِّفرتا فعليًا؛ الباقي بقي كما هو كـ const-string خام
    assert len(report.strings_encrypted) <= 2
    assert text.count('const-string v') >= 2  # السلاسل غير-المُشفَّرة بقيت const-string


def test_explicit_seed_is_fully_reproducible():
    """إصلاح تعاقد --seed: كان build_seed_bytes/device_salt_bytes دائمًا عشوائيين حقيقيين
    بغض النظر عن master_seed، فيُعطي --seed نفس التسمية لكن تشفيرًا مختلفًا في كل مرة رغم أن
    CLI/README يوثّقان 'إعادة إنتاج بناء محدد'. الآن deterministic=True (تُفعَّل فقط حين يُحدِّد
    المستخدم --seed) تجعل كل شيء — بما فيه مادة التشفير نفسها — متطابقًا حرفيًا بين تشغيلين."""
    from relopin.polymorphic import build_plan

    p1 = build_plan(999, deterministic=True)
    p2 = build_plan(999, deterministic=True)
    assert p1.runtime_package == p2.runtime_package
    assert p1.runtime_class == p2.runtime_class
    assert p1.build_seed_bytes == p2.build_seed_bytes
    assert p1.device_salt_bytes == p2.device_salt_bytes

    # المسار الافتراضي (بدون --seed) يجب أن يبقى عشوائيًا حقيقيًا كما كان (لا تراجع أمني)
    p3 = build_plan(999, deterministic=False)
    p4 = build_plan(999, deterministic=False)
    assert p3.build_seed_bytes != p4.build_seed_bytes


def test_locals_count_increases_exactly_by_candidates_in_that_method(work_dir):
    honey_cfg = Path(__file__).resolve().parent.parent / "honeytraps.example.json"
    report = si.run_build(
        apk_decoded_dir=str(work_dir),
        master_seed=777,
        honey_cfg_path=str(honey_cfg),
        string_enc_probability_pct=100,
    )
    text = (work_dir / "smali/com/example/app/MainActivity.smali").read_text(encoding="utf-8")

    # onCreate كان .locals 3 وفيه مرشّحان (السلسلتان الطويلتان) => يجب أن يصبح .locals 5
    m = re.search(r"public onCreate.*?\.locals (\d+)", text, re.DOTALL)
    assert m
    assert int(m.group(1)) == 5  # 3 + 2

    # noSecrets كان .locals 2 وفيه "ok" (قصيرة جدًا < 4 أحرف => غير مؤهَّلة) => يبقى .locals 2
    m2 = re.search(r"public noSecrets.*?\.locals (\d+)", text, re.DOTALL)
    assert m2
    assert int(m2.group(1)) == 2
