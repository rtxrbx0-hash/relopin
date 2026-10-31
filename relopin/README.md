# 🛡️ relopin

**Polymorphic Android app-protection toolkit** — encrypts smali string literals, injects decoy honey-trap functions, and produces a **unique build every run**.

Python orchestrates. Rust handles crypto. **Zero third-party deps** (except `apktool`).

> Tested on a real APK: 1031 strings encrypted, 3 honey traps injected, app installed and ran on a physical device.

---

## Features

| Feature | Status |
|---|---|
| 🎲 Polymorphic (random package/class names per build) | ✅ |
| 🔐 String encryption (SHA-256 counter-mode, Rust) | ✅ |
| 🍯 Honey traps (JSON-configurable) | ✅ |
| 📊 HTML protection report | ✅ |
| 🧩 Real smali injection via `apktool` | ✅ |
| 🧪 22 automated tests | ✅ |

---

## What it does **not** protect

Being explicit is part of the design:

- ❌ `res/values/strings.xml` — UI strings are **not encrypted** (smali only)
- ❌ Dynamic analysis (Frida, Xposed) — out of scope
- ❌ Hardware-unique keys — same APK ships to all devices
- ❌ Code obfuscation — use R8/ProGuard (relopin is **complementary**, not a replacement)

**A determined reverse-engineer can extract `BUILD_SEED`/`DEVICE_SALT` from smali and re-run `SHA256(seed||salt)`.** Treat relopin as *anti-grep*, not *anti-reverse*.

---

## Install

```bash
cd rust_core && cargo build --release && cd ..
pip install -e .
relopin --help
```

**Requires:** Rust stable, Python ≥ 3.9, `apktool`, `apksigner` (Android SDK build-tools).

---

## Usage

```bash
relopin protect app.apk \
  -o app-protected.apk \
  --honey-config honeytraps.example.json \
  --report report.html \
  --string-probability 60
```

Then **sign** (relopin never touches signing keys):

```bash
apksigner sign --ks your.keystore app-protected.apk
```

### CLI options

| Option | Default | Description |
|---|---|---|
| `apk` | — | Input APK |
| `-o, --out` | — | Output APK (unsigned) |
| `--honey-config` | — | JSON honey traps (required) |
| `--report` | `relopin_report.html` | HTML report |
| `--seed` | random | Reproducible build (debug only) |
| `--string-probability` | `40` | % of strings to encrypt |
| `--max-files` | all | Limit smali files (fast test) |
| `--apktool-cmd` | PATH | Custom apktool |

Every run **without `--seed`** produces a different build.

---

## Honey traps

Edit `honeytraps.example.json`:

```json
{
  "traps": [
    {
      "name_hint": "fake_api_key",
      "fake_value": "RLPN-HONEY-7f3a9c21-DO-NOT-USE",
      "return_type": "string"
    },
    {
      "name_hint": "fake_endpoint",
      "fake_value": "https://decoy.example.invalid/v2/validate",
      "return_type": "string"
    }
  ]
}
```

relopin injects static methods returning these values. **You** monitor their use on your server — relopin never contacts any server.

Supported `return_type`: `"string"`, `"int"`.

---

## How it works

1. `apktool d` — decode APK to smali
2. Generate random `RelopinRuntime` package/class + `BUILD_SEED` + `DEVICE_SALT`
3. Inject `RelopinRuntime.smali` (with `decrypt([B)` via `MessageDigest`)
4. Encrypt `const-string` literals → replace with `fill-array-data` + `decrypt()`
5. Inject honey-trap methods
6. `apktool b` — rebuild
7. Write HTML report

---

## Test

```bash
cargo build --release --manifest-path rust_core/Cargo.toml
pytest tests/ -v
```

22 tests: SHA-256 vectors, cipher roundtrip, register shifting, honey traps, `_unescape` Unicode safety, register-budget overflow, `--seed` reproducibility, batch encryption, full injection roundtrip.

---

## Changelog (highlights)

### v0.3
- 🔴 Fixed `pip install -e .` (failed on modern setuptools)
- 🔴 Fixed `_unescape` corrupting non-ASCII text
- 🟠 Fixed register overflow past `v15` (broke `apktool b`)
- 🟠 Fixed `--seed` not actually reproducing builds
- 🟢 Removed unused `dist/` binary, added `.gitignore`

### v0.2
- 🔴 Fixed encryption/decryption mismatch (salt was empty at build)
- 🔴 Fixed unsafe scratch-register allocation
- 🟠 Fixed state leaking between methods
- 🟡 Added 18 tests, batch encryption, removed dead HKDF code

---

## Contributing

Help wanted with:
- More smali edge cases (`.registers`, unusual opcodes)
- More honey-trap return types (`boolean`, `long`)
- **Signature-certificate binding** (roadmap item — the real anti-reverse fix)
- Testing on real-world apps (report what works/breaks)

```bash
cargo build --release --manifest-path rust_core/Cargo.toml
pytest tests/ -v
```

Open an issue first for large changes.

---

## License

**Apache License 2.0** — see [LICENSE](LICENSE). Free for commercial use, patent grant included, attribution required.

---

## Disclaimer

Defensive tool for **your own** apps (like DexGuard/Arxan). Use only on applications you own or have explicit permission to modify. **Do not** use on third-party apps — that violates copyright law in most jurisdictions.
