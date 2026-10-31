"""
smali_injector.py (v0.2 — بعد مراجعة أمنية خارجية أصلحت عدة ثغرات حقيقية)
--------------------------------------------------------------------------
التغييرات الجوهرية عن v0.1:

  #1 🔴 إصلاح: التشفير وقت البناء كان يستخدم salt="" بينما RelopinRuntime يحسب deviceSalt()
     من Build.* على الجهاز → فشل فك تشفير دائم. الآن plan.device_salt_bytes يُضمَّن في كل من
     التشفير وملف smali الناتج (حقل DEVICE_SALT ثابت)، فيتطابقان دائمًا. راجع polymorphic.py
     و templates/RelopinRuntime.smali.tpl.

  #2 🔴 إصلاح: حجز سجل scratch لم يكن مضمونًا بالكامل أمام كل الاحتمالات (خصوصًا لو كانت
     دوال تحتوي على سجلات صريحة قرب حافة .locals). الآن: لكل method تحوي حقنًا، كل السجلات
     الصريحة المحلية (vN الأصلية) تُزاح صراحة بمقدار K (عدد النصوص المحقونة في تلك الدالة
     فقط)، وسجلات scratch الجديدة تُحجز حصريًا عند v0..v(K-1) — منطقة مضمونة فارغة 100% لأنها
     لم تكن موجودة إطلاقًا قبل الإزاحة، بغض النظر عن أي افتراضات حول ترميز pN/vN الأصلي.

  #3 🟠 إصلاح: الحالة (`locals_value`, `pending_arrays`, ...) كانت تُصفَّر فقط لكل ملف لا لكل
     method → تسرّب حالة بين methods. الآن: كل method block يُعالَج بمعزل تام، حالة جديدة من
     الصفر.

  #4 🟠 تخفيف الادعاء: التوثيق أصبح صريحًا أن الحماية "تتطلب تنفيذًا فعليًا داخل ART" (تمنع
     الاستخراج الساكن الفوري بـ grep/strings) وليست "استحالة فك تشفير مطلقة" — محلل مُصمِّم
     يعيد تنفيذ SHA256(seed||salt) يدويًا سيفك التشفير لو استخرج القيم من APK نفسه. هذا متوقَّع
     ومُوثَّق، لا نبالغ في وصفه.

  #5 🟠 إصلاح: الآن ندعم `const-string/jumbo`، نتجاهل بأمان ما بداخل `.annotation`/
     `.array-data` (كانت تُعامَل كأي سطر عادي سابقًا وقد تُطابَق خطأً)، ونزيل أي تعليق لاحق
     على نفس سطر `const-string` قبل المطابقة.

  #9 🟡 إصلاح أداء: كل النصوص المؤهَّلة للتشفير عبر الملف بأكمله تُجمَع أولاً، ثم تُشفَّر في
     استدعاء subprocess واحد فقط (`batch-encrypt-simple`) بدل استدعاء منفصل لكل نص.
"""
from __future__ import annotations

import dataclasses
import re
from pathlib import Path

from . import honey as honey_mod
from . import rustcore
from .polymorphic import BuildPlan, smali_byte_array_literal
from .seed import SplitMix64

CONST_STRING_RE = re.compile(r'^(\s*)const-string(/jumbo)? (v\d+), "((?:[^"\\]|\\.)*)"\s*$')
LOCALS_RE = re.compile(r'^(\s*)\.locals (\d+)\s*$')
REGISTERS_RE = re.compile(r'^(\s*)\.registers (\d+)\s*$')
METHOD_RE = re.compile(r'^\s*\.method\b')
END_METHOD_RE = re.compile(r'^\s*\.end method\s*$')

# يحلّل توقيع .method كاملاً (access flags + اسم + بارامترات + نوع الإرجاع) لحساب عدد
# سجلات p (البارامترات) الفعلي — مطلوب لإصلاح ثغرة فيض السجلات (انظر _method_register_budget).
METHOD_SIG_RE = re.compile(
    r'^\s*\.method\s+(?P<flags>(?:[a-z][a-z-]*\s+)*)(?P<name>\S+?)\((?P<params>[^)]*)\)(?P<ret>.+)\s*$'
)

# أسطر معلومات debug التي تُسمّي متغيرًا محليًا بسجل v صريح (وليس p) — baksmali يُصدرها دائمًا
# بهذا الشكل حتى لو كان المتغير يُسمّي بارامتر، لذا يجب إزاحتها مثل أي vN عادي (إصلاح منفصل:
# كانت تُترَك دون إزاحة لأنها غالبًا تحوي علامات اقتباس، فتسقط في مسار "تحفّظ" الخاص بالنصوص).
_DEBUG_LOCAL_RE = re.compile(r'^(\s*\.(?:local|end local|restart local)\s+)v(\d+)(.*)$')

_REG_TOKEN_RE = re.compile(r'(?<=[\s{,])v(\d+)(?=[\s,}]|$)')

_SKIP_PATTERNS = re.compile(
    r"^(android\.|java\.|kotlin\.|androidx\.|[a-z0-9_]+/[a-z0-9_/]+$|[A-Za-z0-9_]{1,2}$)"
)


def _strip_trailing_comment(line: str) -> str:
    """يزيل تعليق '# ...' لاحق بنهاية السطر، بشرط ألا يكون '#' داخل نص مقتبس."""
    in_quote = False
    i = 0
    while i < len(line):
        c = line[i]
        if c == '"' and (i == 0 or line[i - 1] != "\\"):
            in_quote = not in_quote
        elif c == "#" and not in_quote:
            return line[:i].rstrip()
        i += 1
    return line


_JAVA_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f",
    '"': '"', "'": "'", "\\": "\\",
}


def _unescape(literal: str) -> str:
    """
    إصلاح ثغرة حرجة: الكود السابق كان `literal.encode("utf-8").decode("unicode_escape")`،
    وهذا يُفسد أي نص غير-ASCII (عربي، فرنسي، صيني، إيموجي...) يحوي أيضًا أي escape واحد
    (حتى `\\n` أو `\\"` بسيطة) في نفس السلسلة: `unicode_escape` يُفسِّر كل بايت UTF-8 فوق
    0x7F كنقطة Latin-1 منفصلة بدل إعادة تجميعها كحرف UTF-8 واحد صحيح، فيتحول النص إلى
    "mojibake" يُشفَّر ويُحقَن بهذا الشكل المُفسَد فعليًا داخل الـ APK (ثم يظهر هكذا فعليًا
    في التطبيق بعد فك التشفير وقت التشغيل — ليس مجرد عرض، بل فساد حقيقي للبيانات المحقونة).
    الإصلاح: مُفسِّر escapes يدوي يعمل مباشرة على نقاط Unicode للسلسلة بايثون (مقروءة أصلاً
    بترميز UTF-8 صحيح من الملف) دون أي تحويل إلى/من بايتات — فلا يَمَسّ أي حرف غير-ASCII
    إطلاقًا، ويُفسِّر فقط \\n \\t \\r \\b \\f \\" \\' \\\\ و\\uXXXX كما يُصدرها baksmali فعليًا.
    """
    if "\\" not in literal:
        return literal
    out: list[str] = []
    i, n = 0, len(literal)
    while i < n:
        c = literal[i]
        if c == "\\" and i + 1 < n:
            nxt = literal[i + 1]
            if nxt == "u" and i + 5 < n:
                hex_digits = literal[i + 2 : i + 6]
                try:
                    out.append(chr(int(hex_digits, 16)))
                    i += 6
                    continue
                except ValueError:
                    pass  # ليس \\uXXXX صالحًا فعليًا — عامله كحرفين عاديين أدناه
            if nxt in _JAVA_ESCAPES:
                out.append(_JAVA_ESCAPES[nxt])
                i += 2
                continue
            # escape غير معروف: احتفظ بالحرفين كما هما (محافظة، لا تخمين)
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


@dataclasses.dataclass
class StringEncryptionEvent:
    file: str
    original_preview: str
    length: int


@dataclasses.dataclass
class HoneyInjectionEvent:
    method_name: str
    name_hint: str


@dataclasses.dataclass
class BuildReport:
    plan: BuildPlan
    runtime_class_fqcn: str
    strings_encrypted: list[StringEncryptionEvent] = dataclasses.field(default_factory=list)
    honey_injected: list[HoneyInjectionEvent] = dataclasses.field(default_factory=list)
    files_touched: set[str] = dataclasses.field(default_factory=set)
    files_scanned: int = 0


def _emit_runtime_class(decoded_dir: Path, plan: BuildPlan) -> str:
    # القالب الآن داخل حزمة relopin نفسها (relopin/relopin/templates/)، لا خارجها — إصلاح
    # عطل تنصيب/تغليف حرج: راجع التعليق في pyproject.toml.
    tpl_path = Path(__file__).resolve().parent / "templates" / "RelopinRuntime.smali.tpl"
    tpl = tpl_path.read_text(encoding="utf-8")

    seed_literal = smali_byte_array_literal(plan.build_seed_bytes, out_register="v0", label="build_seed_data")
    salt_literal = smali_byte_array_literal(plan.device_salt_bytes, out_register="v0", label="device_salt_data")
    rendered = (
        tpl.replace("__PACKAGE__", plan.runtime_package)
        .replace("__CLASSNAME__", plan.runtime_class)
        .replace("    __SEED_BYTES_INIT__", seed_literal)
        .replace("    __SALT_BYTES_INIT__", salt_literal)
    )

    smali_root = decoded_dir / "smali"
    target_dir = smali_root / plan.runtime_package
    target_dir.mkdir(parents=True, exist_ok=True)
    out_file = target_dir / f"{plan.runtime_class}.smali"
    out_file.write_text(rendered, encoding="utf-8")
    return f"L{plan.runtime_package}/{plan.runtime_class};"


def _inject_honey(decoded_dir: Path, plan: BuildPlan, honey_cfg_path: str) -> list[HoneyInjectionEvent]:
    traps = honey_mod.load_honey_config(honey_cfg_path)
    planned = honey_mod.plan_injection_names(traps, plan.honey_seed)

    smali_root = decoded_dir / "smali"
    runtime_file = smali_root / plan.runtime_package / f"{plan.runtime_class}.smali"
    content = runtime_file.read_text(encoding="utf-8")

    methods_src = []
    events = []
    for trap, method_name in planned:
        methods_src.append(honey_mod.smali_trap_method(method_name, trap.fake_value, trap.return_type))
        events.append(HoneyInjectionEvent(method_name=method_name, name_hint=trap.name_hint))

    content = content.rstrip() + "\n\n# --- relopin honey traps (مولّدة تلقائيًا) ---\n\n" + "\n".join(methods_src)
    runtime_file.write_text(content, encoding="utf-8")
    return events


def _iter_smali_files(decoded_dir: Path):
    for smali_dir in sorted(decoded_dir.glob("smali*")):
        if not smali_dir.is_dir():
            continue
        for f in sorted(smali_dir.rglob("*.smali")):
            yield f


def _should_encrypt(rng: SplitMix64, literal: str, probability_pct: int) -> bool:
    if len(literal) < 4:
        return False
    if _SKIP_PATTERNS.match(literal):
        return False
    return rng.randbelow(100) < probability_pct


def _find_method_blocks(lines: list[str]) -> list[tuple[int, int]]:
    """يرجع [(start_idx, end_idx)] لكل method (طرفا الفهرس شاملان، أسطر .method/.end method)."""
    blocks = []
    start = None
    for i, line in enumerate(lines):
        if METHOD_RE.match(line):
            start = i
        elif END_METHOD_RE.match(line) and start is not None:
            blocks.append((start, i))
            start = None
    return blocks


def _param_register_width(params_descriptor: str) -> int:
    """
    عدد سجلات vN/pN التي تشغلها قائمة بارامترات method descriptor smali خامة (مثال:
    'Landroid/os/Bundle;IJLjava/lang/String;' لثلاث بارامترات). الأنواع العريضة J (long) وD
    (double) تشغل سجلّين متتاليين، كل شيء آخر (بما فيه أي مصفوفة بأي بُعد وأي نوع أساسي
    عنصرها) سجل واحد — هذا سلوك dex/smali القياسي.
    يرفع ValueError لو واجه رمزًا غير متوقَّع، فيتعامل المستدعي بمحافظة قصوى (صفر حقن).
    """
    width = 0
    i, n = 0, len(params_descriptor)
    while i < n:
        c = params_descriptor[i]
        if c == "L":
            j = params_descriptor.find(";", i)
            if j == -1:
                raise ValueError(f"نوع كائن غير منتهٍ بـ ';' في: {params_descriptor!r}")
            i = j + 1
            width += 1
        elif c == "[":
            i += 1
            while i < n and params_descriptor[i] == "[":
                i += 1
            if i >= n:
                raise ValueError(f"نوع مصفوفة ناقص في: {params_descriptor!r}")
            if params_descriptor[i] == "L":
                j = params_descriptor.find(";", i)
                if j == -1:
                    raise ValueError(f"نوع كائن غير منتهٍ بـ ';' في: {params_descriptor!r}")
                i = j + 1
            else:
                i += 1  # نوع أساسي واحد لعنصر المصفوفة
            width += 1
        elif c in "JD":
            width += 2
            i += 1
        elif c in "ZBSCIF":
            width += 1
            i += 1
        else:
            raise ValueError(f"رمز نوع غير معروف {c!r} عند الموضع {i} في: {params_descriptor!r}")
    return width


def _method_register_budget(lines: list[str], start: int, end: int, locals_value: int) -> int:
    """
    إصلاح ثغرة حرجة: حقن K سجل scratch يُزيح كل سجل vN أصلي بمقدار K (بما فيها السجلات التي
    تحلّها pN تلقائيًا بعد تحديث .locals). لكن تعليمات dex كثيرة (invoke القصيرة، move،
    new-array، aget/aput...) تُرمَّز بحقل سجل 4-بت فقط — تدعم حصرًا v0..v15. baksmali لا يُصدر
    هذه الصيغ القصيرة إلا لسجلات كانت أصلاً ≤15، فلو دفعت الإزاحة أي سجل منها فوق v15 يفشل
    `apktool b` (إعادة التجميع) على هذا الملف بالكامل برسالة "register out of range" من مُجمِّع
    smali. هذا كان بلا أي حارس إطلاقًا — دوال بعدد سجلات (locals+بارامترات) قريب من 16 (شائع في
    دوال onCreate/listeners الطويلة) كانت تكسر الإعادة-تجميع فعليًا.

    الإصلاح: نحسب هنا الحد الأقصى الآمن K بحيث (locals + بارامترات + K) <= 16 دائمًا — هذا
    تحفّظ 100% آمن بغض النظر عن أي opcode فعلي بالدالة (لأننا لا نحلل bytecode الفعلي، فقط
    نضمن ألا يتجاوز أي سجل القيمة 15 مطلقًا بعد الإزاحة). لو تعذّر تحليل توقيع method، الحد
    الأقصى صفر (صفر حقن لتلك الدالة تحديدًا) — تحفّظ كامل بدل تخمين غير آمن.
    """
    m_sig = METHOD_SIG_RE.match(lines[start])
    if not m_sig:
        return 0

    is_static = re.search(r"(?:^|\s)static(?:\s|$)", m_sig.group("flags")) is not None

    try:
        param_width = _param_register_width(m_sig.group("params"))
    except ValueError:
        return 0

    this_width = 0 if is_static else 1
    existing_registers = locals_value + param_width + this_width
    return max(0, 16 - existing_registers)


@dataclasses.dataclass
class _Candidate:
    line_idx: int
    reg: str
    jumbo: bool
    plaintext: str


def _collect_candidates_in_block(
    lines: list[str], start: int, end: int, rng: SplitMix64, probability_pct: int
) -> list[_Candidate]:
    """
    يرجع candidates داخل method block واحدة. لو الدالة تستخدم `.registers` (نمط قديم لا نضمن
    أمان تحويله دون تحليل توقيع كامل — تحفّظ متعمّد وموثَّق، جزء من إصلاح #2)، أو لا تحوي
    `.locals` إطلاقًا، نرجع قائمة فارغة **دون استهلاك أي قرار rng** (محافظة متسقة، جزء من
    إصلاح #3 — القرارات العشوائية تُستهلك فقط للمرشَّحين الحقيقيين القابلين للتعديل).
    """
    has_locals = any(LOCALS_RE.match(lines[i]) for i in range(start, end + 1))
    has_registers = any(REGISTERS_RE.match(lines[i]) for i in range(start, end + 1))
    if has_registers or not has_locals:
        return []

    candidates = []
    in_annotation = False
    in_arraydata = False
    for i in range(start, end + 1):
        raw = lines[i]
        stripped = raw.strip()
        if stripped.startswith(".annotation"):
            in_annotation = True
            continue
        if stripped == ".end annotation":
            in_annotation = False
            continue
        if stripped.startswith(".array-data"):
            in_arraydata = True
            continue
        if stripped == ".end array-data":
            in_arraydata = False
            continue
        if in_annotation or in_arraydata:
            continue

        cleaned = _strip_trailing_comment(raw)
        m = CONST_STRING_RE.match(cleaned)
        if not m:
            continue
        _indent, jumbo_flag, reg, literal = m.groups()
        plaintext = _unescape(literal)
        if _should_encrypt(rng, plaintext, probability_pct):
            candidates.append(_Candidate(line_idx=i, reg=reg, jumbo=bool(jumbo_flag), plaintext=plaintext))
    return candidates


def _shift_single_register(reg: str, k: int) -> str:
    n = int(reg[1:])
    return f"v{n + k}"


def _shift_registers_in_line(line: str, k: int) -> str:
    """
    يزيح كل رمز سجل صريح `vN` بمقدار k، **بدون** لمس أي شيء داخل علامات اقتباس (نص مستخدم)
    وبدون لمس رموز `pN` (تُحل تلقائيًا بواسطة مُجمِّع smali بناءً على `.locals` الجديد — هذا هو
    السلوك المعياري الموثَّق لتوجيه `.locals` في أداة smali/baksmali).
    لو كان السطر يحوي علامة اقتباس وليس const-string معروفًا، نتحفَّظ ولا نغيّره إطلاقًا
    (محافظة أفضل من تخمين خاطئ — جزء من إصلاح #5).

    استثناء مُعالَج صراحة: أسطر `.local`/`.end local`/`.restart local` تستخدم ترقيم vN صريح
    (لا pN) حتى لو كانت تُسمّي بارامتر، وغالبًا تحوي علامات اقتباس (اسم/نوع المتغيّر) — بدون
    هذا المسار كانت تسقط في "تحفّظ" النصوص أعلاه وتبقى غير مُزاحة، فتُشير لسجل خاطئ بعد الحقن
    (معلومات debug فاسدة، وإن كانت غير قاتلة للتشغيل عادة).
    """
    m_dbg = _DEBUG_LOCAL_RE.match(line)
    if m_dbg:
        prefix, regnum, rest = m_dbg.groups()
        return f"{prefix}v{int(regnum) + k}{rest}"

    if '"' in line:
        m = CONST_STRING_RE.match(line)
        if m:
            indent, jumbo, reg, literal = m.groups()
            new_reg = _shift_single_register(reg, k)
            jumbo_part = "/jumbo" if jumbo else ""
            return f'{indent}const-string{jumbo_part} {new_reg}, "{literal}"'
        return line

    def repl(m: re.Match) -> str:
        return f"v{int(m.group(1)) + k}"

    return _REG_TOKEN_RE.sub(repl, line)


def _rewrite_block(
    lines: list[str],
    start: int,
    end: int,
    candidates: list[_Candidate],
    ciphertexts: dict[int, bytes],
    runtime_class_fqcn: str,
) -> list[str]:
    """
    يعيد كتابة method block واحدة بأمان:
      - K = عدد المرشّحين المختارين فعليًا في هذه الدالة.
      - كل سجل vN أصلي صريح (خارج النصوص المقتبسة) يُزاح بمقدار +K.
      - سجلات scratch الجديدة v0..v(K-1) تُستخدم حصريًا لتعليمات فك التشفير المحقونة،
        بترتيب ظهورها الطبيعي في الدالة.
      - `.locals` يُحدَّث إلى القيمة الأصلية + K.
    """
    k = len(candidates)
    if k == 0:
        return lines[start : end + 1]

    cand_by_line = {c.line_idx: c for c in candidates}
    ordered_cand_lines = sorted(cand_by_line.keys())
    scratch_index_for_line = {ln: i for i, ln in enumerate(ordered_cand_lines)}

    out: list[str] = []
    array_blocks: list[str] = []

    for i in range(start, end + 1):
        raw = lines[i]

        m_locals = LOCALS_RE.match(raw)
        if m_locals:
            indent, n = m_locals.groups()
            out.append(f"{indent}.locals {int(n) + k}")
            continue

        if i in cand_by_line:
            cand = cand_by_line[i]
            scratch_reg = f"v{scratch_index_for_line[i]}"
            dest_reg = _shift_single_register(cand.reg, k)
            ciphertext = ciphertexts[i]
            label = f"relopin_arr_{i}_{scratch_index_for_line[i]}"

            indent = raw[: len(raw) - len(raw.lstrip())]
            out.append(f"{indent}const/16 {scratch_reg}, 0x{len(ciphertext):x}")
            out.append(f"{indent}new-array {scratch_reg}, {scratch_reg}, [B")
            out.append(f"{indent}fill-array-data {scratch_reg}, :{label}")
            out.append(
                f"{indent}invoke-static {{{scratch_reg}}}, {runtime_class_fqcn}->decrypt([B)Ljava/lang/String;"
            )
            out.append(f"{indent}move-result-object {dest_reg}")

            block = [f"    :{label}", "    .array-data 1"]
            for b in ciphertext:
                signed = b if b < 128 else b - 256
                block.append(f"        {signed}t")
            block.append("    .end array-data")
            array_blocks.append("\n".join(block))
            continue

        if END_METHOD_RE.match(raw):
            for block in array_blocks:
                out.append(block)
            array_blocks = []
            out.append(raw)
            continue

        out.append(_shift_registers_in_line(raw, k))

    return out


def inject_string_encryption(
    decoded_dir: Path,
    plan: BuildPlan,
    runtime_class_fqcn: str,
    probability_pct: int = 40,
    max_files: int | None = None,
) -> list[StringEncryptionEvent]:
    rng = SplitMix64(plan.string_enc_seed)

    runtime_rel = f"{plan.runtime_package}/{plan.runtime_class}.smali"
    files = [f for f in _iter_smali_files(decoded_dir) if runtime_rel not in str(f)]
    if max_files is not None:
        files = files[:max_files]

    file_lines: dict[Path, list[str]] = {}
    file_candidates: dict[Path, dict[tuple[int, int], list[_Candidate]]] = {}

    all_plaintexts: list[bytes] = []
    plaintext_refs: list[tuple[Path, tuple[int, int], int]] = []

    for f in files:
        try:
            lines = f.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        file_lines[f] = lines
        file_candidates[f] = {}

        for block in _find_method_blocks(lines):
            cands = _collect_candidates_in_block(lines, block[0], block[1], rng, probability_pct)
            if not cands:
                continue

            # إصلاح فيض السجلات: نحسب الحد الآمن K لهذه الدالة تحديدًا (راجع
            # _method_register_budget) ونُقلِّم المرشّحين إليه لو تجاوزوه — بترتيب ظهورهم
            # الطبيعي في الملف، فلا يتأثر أي سجل بالإزاحة فوق v15 إطلاقًا مهما كان opcode
            # الفعلي. قرارات rng نفسها (_should_encrypt) لا تتغيّر — فقط التقليم يتغيّر، فتبقى
            # نتائج --seed قابلة لإعادة الإنتاج بغضّ النظر عن هذا الإصلاح.
            m_locals = next(
                (LOCALS_RE.match(lines[i]) for i in range(block[0], block[1] + 1) if LOCALS_RE.match(lines[i])),
                None,
            )
            locals_value = int(m_locals.group(2)) if m_locals else 0
            budget = _method_register_budget(lines, block[0], block[1], locals_value)
            if len(cands) > budget:
                cands = cands[:budget]
            if not cands:
                continue

            file_candidates[f][block] = cands
            for c in cands:
                all_plaintexts.append(c.plaintext.encode("utf-8"))
                plaintext_refs.append((f, block, c.line_idx))

    if not all_plaintexts:
        return []

    # إصلاح الثغرة #9: استدعاء واحد للنواة يشفّر كل النصوص المختارة في كامل الـ APK دفعة واحدة،
    # بدل استدعاء subprocess منفصل لكل نص (كان يستغرق دقائق على APK متوسط الحجم).
    all_ciphertexts = rustcore.batch_encrypt_simple(
        plan.build_seed_bytes, plan.device_salt_bytes, all_plaintexts
    )
    ct_by_ref = {ref: ct for ref, ct in zip(plaintext_refs, all_ciphertexts)}

    events: list[StringEncryptionEvent] = []
    for f, blocks_map in file_candidates.items():
        if not blocks_map:
            continue
        new_lines = list(file_lines[f])

        # الكتابة من آخر كتلة إلى أولها حتى لا تتغيّر فهارس الكتل السابقة عند إدراج أسطر إضافية.
        for block in sorted(blocks_map.keys(), key=lambda b: -b[0]):
            cands = blocks_map[block]
            ciphertexts_for_block = {c.line_idx: ct_by_ref[(f, block, c.line_idx)] for c in cands}
            rewritten = _rewrite_block(new_lines, block[0], block[1], cands, ciphertexts_for_block, runtime_class_fqcn)
            new_lines[block[0] : block[1] + 1] = rewritten
            for c in cands:
                events.append(
                    StringEncryptionEvent(
                        file=str(f.relative_to(decoded_dir)),
                        original_preview=(c.plaintext[:24] + ("…" if len(c.plaintext) > 24 else "")),
                        length=len(c.plaintext),
                    )
                )

        f.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    return events


def run_build(
    apk_decoded_dir: str,
    master_seed: int,
    honey_cfg_path: str,
    string_enc_probability_pct: int = 40,
    max_files: int | None = None,
    deterministic: bool = False,
) -> BuildReport:
    """
    `deterministic=True` يُستخدم فقط حين يُمرِّر المستخدم `--seed` صراحة (إعادة إنتاج بناء
    محدَّد للـ debugging) — راجع التعليق في polymorphic.build_plan لتفاصيل إصلاح هذا التعاقد.
    """
    from .polymorphic import build_plan

    decoded_dir = Path(apk_decoded_dir)
    plan = build_plan(master_seed, deterministic=deterministic)

    runtime_fqcn = _emit_runtime_class(decoded_dir, plan)
    honey_events = _inject_honey(decoded_dir, plan, honey_cfg_path)
    string_events = inject_string_encryption(
        decoded_dir, plan, runtime_fqcn, probability_pct=string_enc_probability_pct, max_files=max_files
    )

    report = BuildReport(
        plan=plan,
        runtime_class_fqcn=runtime_fqcn,
        strings_encrypted=string_events,
        honey_injected=honey_events,
        files_touched={e.file for e in string_events},
        files_scanned=len(list(_iter_smali_files(decoded_dir))),
    )
    return report
