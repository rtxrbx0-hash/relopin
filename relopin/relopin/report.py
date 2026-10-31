"""
report.py
---------
يبني ملف HTML واحد self-contained (بدون أي اعتمادية خارجية — CSS/JS كلها inline) يعرض:
  - ملخص البناء (seed، اسم/حزمة RelopinRuntime المولّدة)
  - خريطة الملفات التي حُقن فيها تشفير نصوص (مع عدد السلاسل لكل ملف، بدون كشف السر نفسه
    كاملاً — فقط preview مقصوص لأن التقرير قد يُشارَك مع فريق أو يُرفع لنظام CI)
  - قائمة فخاخ العسل المحقونة (الاسم المنطقي الذي اختاره المطور + اسم الدالة المولَّد)
  - لا يحتوي التقرير على القيم الزائفة الكاملة لفخاخ العسل عمدًا؛ المطور يعرفها من
    honeytraps.json نفسه، والتقرير فقط يؤكد أنها حُقنت وأين.
"""
from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from .smali_injector import BuildReport

_TEMPLATE = """<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<title>relopin — تقرير الحماية</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root{
    --bg:#0b0f14; --panel:#121823; --panel2:#0f141d; --text:#e6edf3; --muted:#8b98a5;
    --accent:#36d399; --accent2:#f59e0b; --danger:#ef4444; --border:#1f2937;
  }
  @media (prefers-color-scheme: light){
    :root{ --bg:#f6f7f9; --panel:#ffffff; --panel2:#f0f2f5; --text:#15202b; --muted:#5b6b7b; --border:#e2e6ea; }
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",Tahoma,Arial,sans-serif;line-height:1.6}
  header{padding:28px 20px;border-bottom:1px solid var(--border);background:var(--panel)}
  h1{margin:0 0 4px;font-size:22px}
  .sub{color:var(--muted);font-size:13px}
  main{max-width:980px;margin:0 auto;padding:20px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:18px 0}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px}
  .stat{font-size:28px;font-weight:700;color:var(--accent)}
  .stat.amber{color:var(--accent2)}
  .label{color:var(--muted);font-size:12px;margin-top:4px}
  section{margin-top:28px}
  h2{font-size:16px;border-inline-start:4px solid var(--accent);padding-inline-start:10px}
  table{width:100%;border-collapse:collapse;font-size:13px;background:var(--panel);border-radius:10px;overflow:hidden;border:1px solid var(--border)}
  th,td{padding:9px 12px;text-align:start;border-bottom:1px solid var(--border)}
  th{background:var(--panel2);color:var(--muted);font-weight:600}
  tr:last-child td{border-bottom:none}
  code{background:var(--panel2);padding:2px 6px;border-radius:6px;font-size:12px}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;background:var(--panel2);color:var(--accent)}
  .honey{color:var(--accent2)}
  footer{color:var(--muted);font-size:12px;text-align:center;padding:30px 20px}
  .empty{color:var(--muted);font-style:italic;padding:14px}
</style>
</head>
<body>
<header>
  <h1>🛡️ relopin — تقرير الحماية</h1>
  <div class="sub">build seed: <code>__MASTER_SEED__</code> &nbsp;·&nbsp; نواة التشغيل: <code>__RUNTIME_CLASS__</code></div>
</header>
<main>
  <div class="grid">
    <div class="card"><div class="stat">__FILES_SCANNED__</div><div class="label">ملف smali تم فحصه</div></div>
    <div class="card"><div class="stat">__FILES_TOUCHED__</div><div class="label">ملف عُتِّم فيه نص واحد على الأقل</div></div>
    <div class="card"><div class="stat">__STRINGS_COUNT__</div><div class="label">سلسلة نصية مُشفَّرة (device-bound)</div></div>
    <div class="card"><div class="stat amber">__HONEY_COUNT__</div><div class="label">فخ عسل مُحقَن</div></div>
  </div>

  <section>
    <h2>خريطة تعتيم النصوص (حسب الملف)</h2>
    __STRINGS_TABLE__
  </section>

  <section>
    <h2>فخاخ العسل المُحقَنة</h2>
    __HONEY_TABLE__
  </section>

  <section>
    <h2>تفاصيل خام (JSON)</h2>
    <details><summary class="pill">عرض/إخفاء</summary>
      <pre style="overflow:auto;background:var(--panel2);padding:12px;border-radius:10px;font-size:12px">__RAW_JSON__</pre>
    </details>
  </section>
</main>
<footer>تم توليده بواسطة relopin — لا يحتوي هذا التقرير على القيم الزائفة الكاملة لفخاخ العسل ولا على النصوص الأصلية كاملة.</footer>
</body>
</html>
"""


def _strings_table(report: BuildReport) -> str:
    if not report.strings_encrypted:
        return '<div class="empty">لم يُشفَّر أي نص في هذا البناء.</div>'
    per_file = Counter(e.file for e in report.strings_encrypted)
    rows = "\n".join(
        f"<tr><td><code>{html.escape(f)}</code></td><td>{n}</td></tr>"
        for f, n in sorted(per_file.items(), key=lambda kv: -kv[1])
    )
    return f"<table><thead><tr><th>الملف</th><th>عدد السلاسل المشفّرة</th></tr></thead><tbody>{rows}</tbody></table>"


def _honey_table(report: BuildReport) -> str:
    if not report.honey_injected:
        return '<div class="empty">لا توجد فخاخ عسل مُفعَّلة لهذا البناء.</div>'
    rows = "\n".join(
        f'<tr><td class="honey">{html.escape(e.name_hint)}</td><td><code>{html.escape(e.method_name)}</code></td></tr>'
        for e in report.honey_injected
    )
    return f"<table><thead><tr><th>الاسم المنطقي (من إعدادك)</th><th>اسم الدالة المولَّد</th></tr></thead><tbody>{rows}</tbody></table>"


def render_html_report(report: BuildReport) -> str:
    raw = {
        "master_seed": report.plan.master_seed,
        "runtime_package": report.plan.runtime_package,
        "runtime_class": report.plan.runtime_class,
        "files_scanned": report.files_scanned,
        "files_touched": sorted(report.files_touched),
        "strings_encrypted_count": len(report.strings_encrypted),
        "honey_injected": [e.method_name for e in report.honey_injected],
    }
    out = _TEMPLATE
    out = out.replace("__MASTER_SEED__", str(report.plan.master_seed))
    out = out.replace("__RUNTIME_CLASS__", html.escape(report.runtime_class_fqcn))
    out = out.replace("__FILES_SCANNED__", str(report.files_scanned))
    out = out.replace("__FILES_TOUCHED__", str(len(report.files_touched)))
    out = out.replace("__STRINGS_COUNT__", str(len(report.strings_encrypted)))
    out = out.replace("__HONEY_COUNT__", str(len(report.honey_injected)))
    out = out.replace("__STRINGS_TABLE__", _strings_table(report))
    out = out.replace("__HONEY_TABLE__", _honey_table(report))
    out = out.replace("__RAW_JSON__", html.escape(json.dumps(raw, ensure_ascii=False, indent=2)))
    return out


def write_report(report: BuildReport, out_path: str) -> None:
    Path(out_path).write_text(render_html_report(report), encoding="utf-8")
