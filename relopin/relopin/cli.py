from __future__ import annotations

import argparse
import sys

from . import apktool_wrapper
from .report import write_report
from .seed import new_build_seed
from .smali_injector import run_build


def cmd_protect(args: argparse.Namespace) -> int:
    # إصلاح: --seed كان يُعيد إنتاج التسمية/الاختيار فقط، لا مادة التشفير الفعلية (كانت دائمًا
    # عشوائية حقيقية بغض النظر عن --seed) — راجع التعليق في polymorphic.build_plan. الآن
    # `explicit_seed` تُفعِّل الاشتقاق الحتمي الكامل فقط حين يطلبه المستخدم صراحة.
    explicit_seed = args.seed is not None
    master_seed = args.seed if explicit_seed else new_build_seed()
    print(f"[relopin] build seed = {master_seed}" + (" (--seed صريح: بناء قابل لإعادة الإنتاج بالكامل)" if explicit_seed else ""))

    print("[relopin] فك تجميع الـ APK عبر apktool ...")
    apktool_wrapper.decode(args.apk, args.work_dir, apktool_cmd=args.apktool_cmd)

    print("[relopin] تشغيل المحرك المتعدد الأشكال (تسمية + تشفير نصوص + فخاخ عسل) ...")
    report = run_build(
        apk_decoded_dir=args.work_dir,
        master_seed=master_seed,
        honey_cfg_path=args.honey_config,
        string_enc_probability_pct=args.string_probability,
        max_files=args.max_files,
        deterministic=explicit_seed,
    )

    print(f"[relopin] نواة التشغيل: {report.runtime_class_fqcn}")
    print(f"[relopin] سلاسل مُشفَّرة: {len(report.strings_encrypted)} في {len(report.files_touched)} ملف")
    print(f"[relopin] فخاخ عسل محقونة: {len(report.honey_injected)}")

    print("[relopin] إعادة تجميع الـ APK عبر apktool ...")
    apktool_wrapper.build(args.work_dir, args.out, apktool_cmd=args.apktool_cmd)

    if args.report:
        write_report(report, args.report)
        print(f"[relopin] تقرير الحماية: {args.report}")

    print(f"[relopin] تم. APK المحمي: {args.out}")
    print("[relopin] تذكير: وقّع الـ APK الناتج بمفتاحك (apksigner / jarsigner) قبل التوزيع —")
    print("          relopin عمدًا لا يتعامل مع مفاتيح التوقيع.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="relopin", description="relopin — أداة حماية تطبيقات Android متعددة الأشكال")
    sub = p.add_subparsers(dest="command", required=True)

    protect = sub.add_parser("protect", help="يحمي APK: تعتيم + تشفير نصوص + فخاخ عسل + تقرير")
    protect.add_argument("apk", help="مسار الـ APK المدخل")
    protect.add_argument("-o", "--out", required=True, help="مسار الـ APK الناتج (غير موقَّع)")
    protect.add_argument("--work-dir", default="relopin_work", help="مجلد عمل apktool decode")
    protect.add_argument("--honey-config", required=True, help="ملف JSON لفخاخ العسل (انظر honeytraps.example.json)")
    protect.add_argument("--report", default="relopin_report.html", help="مسار تقرير HTML (فارغ لتعطيله)")
    protect.add_argument("--seed", type=int, default=None, help="إجبار seed محدد (لإعادة إنتاج بناء سابق، debug فقط)")
    protect.add_argument("--string-probability", type=int, default=40, help="نسبة%% السلاسل المرشَّحة التي تُشفَّر فعليًا")
    protect.add_argument("--max-files", type=int, default=None, help="حد أقصى لعدد ملفات smali تُعالَج (للاختبار السريع)")
    protect.add_argument("--apktool-cmd", default=None, help="مسار apktool إن لم يكن في PATH")
    protect.set_defaults(func=cmd_protect)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
