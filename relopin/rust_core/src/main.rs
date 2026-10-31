mod sha256;

use std::env;
use std::io::{self, BufRead, Write};
use std::process::exit;

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// إصلاح الثغرة #7: hex غير صالح كان يتحوّل صمتًا إلى أصفار (unwrap_or(0))، مما يخفي أخطاء
/// إدخال حقيقية وينتج مفاتيح/نصوصًا خاطئة دون أي تحذير. الآن: أي خطأ hex يوقف البرنامج فورًا
/// برسالة واضحة على stderr بدل الاستمرار بقيمة صامتة خاطئة.
fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        eprintln!("خطأ: سلسلة hex بطول فردي غير صالحة: {:?}", s);
        exit(1);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match u8::from_str_radix(&s[i..i + 2], 16) {
            Ok(b) => out.push(b),
            Err(_) => {
                eprintln!("خطأ: بايت hex غير صالح عند الموضع {}: {:?}", i, &s[i..i + 2]);
                exit(1);
            }
        }
        i += 2;
    }
    out
}

/// key = SHA256(build_seed || device_salt). مطابق تمامًا لما ينفّذه RelopinRuntime.smali على
/// الجهاز عبر java.security.MessageDigest (تم التحقق بينهما عبر hashlib في relopin/tests).
fn derive_key_simple(build_seed: &[u8], device_salt: &[u8]) -> [u8; 32] {
    let mut input = build_seed.to_vec();
    input.extend_from_slice(device_salt);
    sha256::sha256(&input)
}

/// keystream block_i = SHA256(key || ascii_decimal(i)); ciphertext = plaintext XOR keystream.
/// XOR متماثل: نفس الدالة للتشفير وفك التشفير.
fn xor_stream_simple(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter: u64 = 0;
    let mut block = {
        let mut input = key.to_vec();
        input.extend_from_slice(counter.to_string().as_bytes());
        sha256::sha256(&input)
    };
    let mut pos = 0usize;
    for &b in data {
        if pos == block.len() {
            counter += 1;
            let mut input = key.to_vec();
            input.extend_from_slice(counter.to_string().as_bytes());
            block = sha256::sha256(&input);
            pos = 0;
        }
        out.push(b ^ block[pos]);
        pos += 1;
    }
    out
}

/// PRNG بسيط (splitmix64) — يطابق منطق seed.py في بايثون، يُستخدم لتوليد أسماء junk سريعًا.
struct SplitMix64 {
    state: u64,
}
impl SplitMix64 {
    fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

const JUNK_SYLLABLES: &[&str] = &[
    "zx", "qr", "vk", "mp", "lt", "br", "nd", "wf", "jk", "yh", "cz", "pq", "gx", "tv", "sk", "dr",
];

fn gen_junk_name(rng: &mut SplitMix64) -> String {
    let len = 3 + (rng.next_u64() % 4) as usize;
    let mut s = String::from("a");
    for _ in 0..len {
        let syll = JUNK_SYLLABLES[(rng.next_u64() as usize) % JUNK_SYLLABLES.len()];
        s.push_str(syll);
    }
    s
}

fn usage() -> ! {
    eprintln!(
        "relopin-core <cmd> [args]\n\
         \n\
         derive-key-simple    <build_seed_hex> <device_salt_hex>\n\
         xor-stream-simple    <key_hex> <data_hex>                  (متماثل، تشفير=فك تشفير)\n\
         batch-encrypt-simple <build_seed_hex> <device_salt_hex>    (يقرأ أسطر plaintext hex\n\
                                                                       من stdin، سطر ciphertext hex\n\
                                                                       لكل واحد على stdout — استدعاء\n\
                                                                       واحد للبناء الكامل بدل آلاف\n\
                                                                       الاستدعاءات، إصلاح الثغرة #9)\n\
         gen-junk   <seed_u64> <count>\n\
         sha256     <data_hex>\n"
    );
    exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }
    match args[1].as_str() {
        "derive-key-simple" => {
            if args.len() != 4 {
                usage();
            }
            let seed = hex_decode(&args[2]);
            let salt = hex_decode(&args[3]);
            let key = derive_key_simple(&seed, &salt);
            println!("{}", hex_encode(&key));
        }
        "xor-stream-simple" => {
            if args.len() != 4 {
                usage();
            }
            let key_bytes = hex_decode(&args[2]);
            if key_bytes.len() != 32 {
                eprintln!("خطأ: المفتاح يجب أن يكون 32 بايت (64 حرف hex)، وُجد {} بايت", key_bytes.len());
                exit(1);
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            let data = hex_decode(&args[3]);
            let out = xor_stream_simple(&key, &data);
            println!("{}", hex_encode(&out));
        }
        "batch-encrypt-simple" => {
            // إصلاح الثغرة #9: استدعاء subprocess واحد للبناء كله بدل واحد لكل سلسلة نصية.
            if args.len() != 4 {
                usage();
            }
            let seed = hex_decode(&args[2]);
            let salt = hex_decode(&args[3]);
            let key = derive_key_simple(&seed, &salt);

            let stdin = io::stdin();
            let stdout = io::stdout();
            let mut out_lock = stdout.lock();
            for line in stdin.lock().lines() {
                let line = line.expect("فشل قراءة سطر من stdin");
                if line.trim().is_empty() {
                    continue;
                }
                let plaintext = hex_decode(&line);
                let ciphertext = xor_stream_simple(&key, &plaintext);
                writeln!(out_lock, "{}", hex_encode(&ciphertext)).expect("فشل الكتابة على stdout");
            }
        }
        "gen-junk" => {
            if args.len() != 4 {
                usage();
            }
            let seed: u64 = args[2].parse().unwrap_or_else(|_| {
                eprintln!("خطأ: seed يجب أن يكون عددًا صحيحًا: {:?}", args[2]);
                exit(1);
            });
            let count: u64 = args[3].parse().unwrap_or_else(|_| {
                eprintln!("خطأ: count يجب أن يكون عددًا صحيحًا: {:?}", args[3]);
                exit(1);
            });
            let mut rng = SplitMix64::new(seed);
            for _ in 0..count {
                println!("{}", gen_junk_name(&mut rng));
            }
        }
        "sha256" => {
            if args.len() != 3 {
                usage();
            }
            let data = hex_decode(&args[2]);
            println!("{}", hex_encode(&sha256::sha256(&data)));
        }
        _ => usage(),
    }
}
