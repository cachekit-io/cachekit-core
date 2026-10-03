//! Per-op instruction counts (Ir/op) for cachekit-core's hot paths, and the
//! regression gate on them: `make perf-ir`.
//!
//! Wall clock cannot gate a 1% regression on a shared host, and Criterion
//! (`hot_path`) picks its iteration count from wall time, so its total under
//! valgrind cannot be divided by a known count. This target runs every
//! operation a fixed number of times instead:
//!
//! - Each case is its own process, `perf_ir run <case> <n>`. It builds the
//!   case's inputs, runs the operation once to warm it (lazy statics, CPU
//!   feature detection, the allocator's free lists), then runs it `n` times.
//! - The gate runs each case under `valgrind --tool=cachegrind --cache-sim=no`
//!   at `n = N_OPS` and `n = 0`. Ir/op is `(Ir[N_OPS] - Ir[0]) / N_OPS`, so
//!   process start, setup, the warm-up and exit cancel.
//! - Budgets are keyed by architecture, OS and compiled-in CPU features in
//!   `perf_ir_baselines.json`. A case fails at `FAIL_PCT` over its budget and
//!   warns from `WARN_PCT`. `--update` ratchets budgets down to the measured
//!   figures, never up unless `--allow-increase` says the increase is
//!   deliberate.
//!
//! The counts depend on the compiler, the locked dependencies, the CPU
//! features the binary was compiled for, and the ones valgrind passes through
//! (ring and glibc pick their AES, GHASH and memcpy code from them). Each
//! budget set records the rustc and valgrind it was measured with: the gate
//! notes a different one, and `--update` refuses to ratchet across them,
//! because a set that mixes two toolchains gates neither. Instruction counts
//! ignore cache misses and branch mispredictions: a claimed wall-clock win
//! still needs a wall-clock A/B.

mod common;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::thread;

use cachekit_core::{
    check_msgpack_structure, derive_domain_key, ByteStorage, Keyring, ZeroKnowledgeEncryptor,
};
use common::msgpack_payload;
use serde::{Deserialize, Serialize};

/// Iterations in the measured run. Counts are exact, so this sets run time,
/// not precision.
const N_OPS: u64 = 1000;
const FAIL_PCT: f64 = 1.0;
const WARN_PCT: f64 = 0.2;
const BASELINES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/perf_ir_baselines.json"
);

/// A small value, a typical value, a large object (as `hot_path`).
const SIZES: [usize; 3] = [64, 1024, 64 * 1024];

/// Operations and whether they take a payload. HKDF derives from the master
/// key and tenant id alone, so it has one case with no size.
const OPS: [(&str, bool); 8] = [
    ("store", true),
    ("retrieve", true),
    ("prescan", true),
    ("encrypt", true),
    ("decrypt", true),
    ("keyring_decrypt", true),
    ("tenant_keyring_decrypt", true),
    ("hkdf", false),
];

const MASTER_KEY: [u8; 32] = [0x42; 32];
const TENANT: &str = "tenant-123";
/// Shaped like an SDK's AAD: version byte, then length-prefixed tenant id and
/// cache key. GHASH cost depends on its length, not its bytes.
const AAD: &[u8] = b"\x03\x00\x00\x00\x0atenant-123\x00\x00\x00\x10ns:bench:func:x";
/// ByteStorage's envelope nesting bound (`decode_envelope`).
const ENVELOPE_MAX_DEPTH: usize = 100;

fn case_ids() -> Vec<String> {
    OPS.iter()
        .flat_map(|&(op, sized)| {
            if sized {
                SIZES.iter().map(|size| format!("{op}/{size}")).collect()
            } else {
                vec![op.to_string()]
            }
        })
        .collect()
}

// ── measured process ────────────────────────────────────────────────────────

/// Build the fixtures and return the operation `case` measures. Setup runs in
/// both the `N_OPS` and the 0 run, so only what the closure does is counted.
fn operation(case: &str) -> Box<dyn FnMut() -> usize> {
    let (op, size) = match case.split_once('/') {
        Some((op, size)) => (op, size.parse().expect("case size is a number")),
        None => (case, 0),
    };
    let payload = msgpack_payload(size);
    let storage = ByteStorage::new(None);
    let envelope = storage.store(&payload, None).unwrap();
    let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
    let key = derive_domain_key(&MASTER_KEY, "encryption", TENANT.as_bytes()).unwrap();
    let ciphertext = encryptor.encrypt_aes_gcm(&payload, &key, AAD).unwrap();
    match op {
        "store" => Box::new(move || storage.store(black_box(&payload), None).unwrap().len()),
        "retrieve" => Box::new(move || storage.retrieve(black_box(&envelope)).unwrap().0.len()),
        "prescan" => Box::new(move || {
            check_msgpack_structure(black_box(&envelope), ENVELOPE_MAX_DEPTH).is_ok() as usize
        }),
        "encrypt" => Box::new(move || {
            encryptor
                .encrypt_aes_gcm(black_box(&payload), &key, AAD)
                .unwrap()
                .len()
        }),
        "decrypt" => Box::new(move || {
            encryptor
                .decrypt_aes_gcm(black_box(&ciphertext), &key, AAD)
                .unwrap()
                .len()
        }),
        // Re-derives the tenant key (HKDF) on every call.
        "keyring_decrypt" => {
            let keyring = Keyring::new(&MASTER_KEY, &[]).unwrap();
            Box::new(move || {
                keyring
                    .decrypt_indexed(&encryptor, black_box(&ciphertext), TENANT, AAD)
                    .unwrap()
                    .0
                    .len()
            })
        }
        // Derived once at for_tenant; the steady-state decrypt surface.
        "tenant_keyring_decrypt" => {
            let keyring = Keyring::new(&MASTER_KEY, &[])
                .unwrap()
                .for_tenant(TENANT)
                .unwrap();
            Box::new(move || {
                keyring
                    .decrypt_indexed(&encryptor, black_box(&ciphertext), AAD)
                    .unwrap()
                    .0
                    .len()
            })
        }
        "hkdf" => Box::new(|| {
            derive_domain_key(black_box(&MASTER_KEY), "encryption", TENANT.as_bytes()).unwrap()[0]
                as usize
        }),
        other => panic!("unknown case {other}"),
    }
}

fn run(case: &str, n: u64) {
    let mut op = operation(case);
    black_box(op());
    for _ in 0..n {
        black_box(op());
    }
}

// ── gate ────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Default)]
struct Baselines {
    method: String,
    platforms: BTreeMap<String, Platform>,
}

#[derive(Serialize, Deserialize, Default)]
struct Platform {
    rustc: String,
    valgrind: String,
    budgets: BTreeMap<String, u64>,
}

/// CPU features this binary was compiled for, beyond the target's baseline.
/// `-C target-cpu` or `-C target-feature` changes the code the compiler and
/// RustCrypto emit (x86-64-v3 takes 18% off `hkdf`), so a build with any of
/// these on is a different instrument with its own budgets. Other RUSTFLAGS
/// and profile overrides are not detected: measure the default build.
const COMPILED_FEATURES: [(&str, bool); 21] = [
    ("sse3", cfg!(target_feature = "sse3")),
    ("ssse3", cfg!(target_feature = "ssse3")),
    ("sse4.1", cfg!(target_feature = "sse4.1")),
    ("sse4.2", cfg!(target_feature = "sse4.2")),
    ("popcnt", cfg!(target_feature = "popcnt")),
    ("avx", cfg!(target_feature = "avx")),
    ("avx2", cfg!(target_feature = "avx2")),
    ("bmi1", cfg!(target_feature = "bmi1")),
    ("bmi2", cfg!(target_feature = "bmi2")),
    ("fma", cfg!(target_feature = "fma")),
    ("lzcnt", cfg!(target_feature = "lzcnt")),
    ("movbe", cfg!(target_feature = "movbe")),
    ("adx", cfg!(target_feature = "adx")),
    ("avx512f", cfg!(target_feature = "avx512f")),
    ("aes", cfg!(target_feature = "aes")),
    ("pclmulqdq", cfg!(target_feature = "pclmulqdq")),
    ("sha", cfg!(target_feature = "sha")),
    ("sha2", cfg!(target_feature = "sha2")),
    ("sha3", cfg!(target_feature = "sha3")),
    ("crc", cfg!(target_feature = "crc")),
    ("lse", cfg!(target_feature = "lse")),
];

/// Budget key: architecture, OS, then any compiled-in CPU features.
fn platform_key() -> String {
    let mut key = format!("{}-{}", env::consts::ARCH, env::consts::OS);
    for (feature, _) in COMPILED_FEATURES.iter().filter(|(_, on)| *on) {
        key.push('+');
        key.push_str(feature);
    }
    key
}

/// Word `word` of `<program> --version`, or "unknown". Only feeds the
/// recorded-with note, so a missing rustc does not stop the gate.
fn version(program: &str, word: usize) -> String {
    Command::new(program)
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.split_whitespace().nth(word).map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn which(program: &str) -> Option<PathBuf> {
    env::split_paths(&env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|path| path.is_file())
}

/// Total Ir of one `run` process under cachegrind.
///
/// The environment is empty, not inherited: its size moves the stack layout,
/// and `VALGRIND_OPTS` or a `~/.valgrindrc` would change what is measured.
fn total_ir(valgrind: &Path, exe: &Path, case: &str, n: u64) -> Result<u64, String> {
    let out = Command::new(valgrind)
        .args([
            "--tool=cachegrind",
            "--cache-sim=no",
            "--cachegrind-out-file=/dev/null",
        ])
        .arg(exe)
        .args(["run", case, &n.to_string()])
        .env_clear()
        .output()
        .map_err(|e| format!("{case} n={n}: cannot start valgrind: {e}"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        return Err(format!("{case} n={n}: {}\n{stderr}", out.status));
    }
    // "==PID== I refs:      1,234,567" (the column padding varies by version)
    stderr
        .lines()
        .find_map(|line| {
            let mut words = line.split_whitespace().skip_while(|w| *w != "I").skip(1);
            match (words.next(), words.next()) {
                (Some("refs:"), Some(count)) => count.replace(',', "").parse().ok(),
                _ => None,
            }
        })
        .ok_or_else(|| format!("{case} n={n}: no 'I refs' line in valgrind output\n{stderr}"))
}

/// Ir/op for each case, in case order. Runs are independent processes, so they
/// parallelise.
fn measure(valgrind: &Path, cases: &[String], jobs: usize) -> Result<Vec<(String, u64)>, String> {
    let exe = env::current_exe().map_err(|e| format!("cannot locate this binary: {e}"))?;
    let runs: Vec<(&str, u64)> = cases
        .iter()
        .flat_map(|case| [(case.as_str(), N_OPS), (case.as_str(), 0)])
        .collect();
    let next = AtomicUsize::new(0);
    let counts: Vec<OnceLock<Result<u64, String>>> = runs.iter().map(|_| OnceLock::new()).collect();
    thread::scope(|scope| {
        for _ in 0..jobs.clamp(1, runs.len()) {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(&(case, n)) = runs.get(i) else { break };
                let _ = counts[i].set(total_ir(valgrind, &exe, case, n));
            });
        }
    });
    let counts = counts
        .into_iter()
        .map(|count| count.into_inner().expect("every run was measured"))
        .collect::<Result<Vec<u64>, String>>()?;
    cases
        .iter()
        .zip(counts.chunks(2))
        .map(|(case, pair)| {
            let (full, setup) = (pair[0], pair[1]);
            match full.checked_sub(setup) {
                Some(delta) if delta > 0 => Ok((case.clone(), (delta + N_OPS / 2) / N_OPS)),
                _ => Err(format!(
                    "{case}: Ir[{N_OPS}] {full} is not above Ir[0] {setup}"
                )),
            }
        })
        .collect()
}

fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// Report lines and whether the gate passes. A case with no budget fails:
/// record it first.
fn compare(budgets: &BTreeMap<String, u64>, measured: &[(String, u64)]) -> (Vec<String>, bool) {
    let mut ok = true;
    let lines = measured
        .iter()
        .map(|(case, ir)| {
            let ir = *ir;
            let Some(&budget) = budgets.get(case) else {
                ok = false;
                return format!(
                    "FAIL  {case:28} {:>10} Ir/op  no budget (run make perf-ir-update)",
                    thousands(ir)
                );
            };
            let pct = (ir as f64 - budget as f64) / budget as f64 * 100.0;
            let verdict = if pct >= FAIL_PCT {
                ok = false;
                "FAIL"
            } else if pct >= WARN_PCT {
                "WARN"
            } else if pct <= -FAIL_PCT {
                "LOWER" // cheaper: ratchet it down with --update if the change touched this path
            } else {
                "ok"
            };
            format!(
                "{verdict:5} {case:28} {:>10} Ir/op  budget {:>10}  {pct:+.2}%",
                thousands(ir),
                thousands(budget)
            )
        })
        .collect();
    (lines, ok)
}

/// New budgets: only ever lower, unless the increase is deliberate.
fn ratchet(budgets: &mut BTreeMap<String, u64>, measured: &[(String, u64)], allow_increase: bool) {
    for (case, ir) in measured {
        let budget = budgets.entry(case.clone()).or_insert(*ir);
        if allow_increase || *ir < *budget {
            *budget = *ir;
        }
    }
}

const USAGE: &str = "\
usage: cargo bench --features encryption --bench perf_ir -- [options]
       (or make perf-ir / make perf-ir-update)

Measures Ir/op for each case under cachegrind and compares it with the budget
in benches/perf_ir_baselines.json. Exit 0 pass, 1 regression, 2 error.

options:
  --case <id>        measure only this case (repeatable)
  --update           write lower measured figures back as budgets
  --allow-increase   with --update, also raise budgets
  --jobs <n>         cachegrind runs at a time (default: min(8, cores))

perf_ir run <case> <n>   the measured process: setup, one warm-up op, n ops";

fn gate(args: &[String]) -> Result<bool, String> {
    let (mut update, mut allow_increase, mut cases) = (false, false, Vec::new());
    let mut jobs = thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(8);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--update" => update = true,
            "--allow-increase" => allow_increase = true,
            "--case" => cases.push(args.next().ok_or("--case needs a case id")?.clone()),
            "--jobs" => {
                jobs = args
                    .next()
                    .and_then(|n| n.parse().ok())
                    .ok_or("--jobs needs a number")?
            }
            "-h" | "--help" => {
                println!("{USAGE}\n\ncases: {}", case_ids().join(" "));
                return Ok(true);
            }
            other => return Err(format!("unknown argument {other}\n\n{USAGE}")),
        }
    }
    if allow_increase && !update {
        return Err("--allow-increase only applies with --update".into());
    }
    let all = case_ids();
    if let Some(unknown) = cases.iter().find(|case| !all.contains(case)) {
        return Err(format!("unknown case {unknown}; cases: {}", all.join(" ")));
    }
    let every_case = cases.is_empty();
    if every_case {
        cases = all;
    }

    let valgrind_bin =
        which("valgrind").ok_or("valgrind not found on PATH: install it (apt install valgrind)")?;
    let text = fs::read_to_string(BASELINES).map_err(|e| format!("{BASELINES}: {e}"))?;
    let mut baselines: Baselines =
        serde_json::from_str(&text).map_err(|e| format!("{BASELINES}: {e}"))?;
    let key = platform_key();
    let (rustc, valgrind) = (version("rustc", 1), version("valgrind", 0));
    let platform = baselines.platforms.entry(key.clone()).or_default();
    if !platform.budgets.is_empty() && (platform.rustc != rustc || platform.valgrind != valgrind) {
        let recorded = format!(
            "budgets for {key} were recorded with rustc {} and {}; this is rustc {rustc} and {valgrind}",
            platform.rustc, platform.valgrind
        );
        // One budget set, one toolchain: ratcheting down across toolchains
        // would mix the two, and a partial re-record would label budgets it
        // never measured with the new versions.
        if update && !(allow_increase && every_case) {
            return Err(format!(
                "{recorded}. Re-record every case on one toolchain: --update --allow-increase, no --case."
            ));
        }
        println!("note: {recorded}. A toolchain change moves the counts.");
    }

    let measured = measure(&valgrind_bin, &cases, jobs)?;
    println!(
        "cachekit-core Ir/op on {key} (rustc {rustc}, {valgrind}): (Ir[{N_OPS}] - Ir[0]) / {N_OPS}"
    );
    // With --update, report against the budgets as written, so the only FAIL
    // left is a regression that --allow-increase did not accept.
    if update {
        ratchet(&mut platform.budgets, &measured, allow_increase);
        platform.rustc = rustc;
        platform.valgrind = valgrind;
    }
    let (lines, ok) = compare(&platform.budgets, &measured);
    println!("{}", lines.join("\n"));
    if update {
        baselines.method = format!(
            "cachegrind Ir per op, (Ir[{N_OPS}] - Ir[0]) / {N_OPS}, one process per case, \
             empty environment; written by benches/perf_ir.rs --update"
        );
        let json = serde_json::to_string_pretty(&baselines).map_err(|e| e.to_string())?;
        fs::write(BASELINES, json + "\n").map_err(|e| format!("{BASELINES}: {e}"))?;
        println!("budgets written to benches/perf_ir_baselines.json");
    }
    println!(
        "{}",
        match (ok, update) {
            (true, _) => "PASS",
            (false, false) => "FAIL: a case regressed by 1% or more, or has no budget",
            (false, true) =>
                "FAIL: a regression stays over budget; raise it only with --allow-increase",
        }
    );
    Ok(ok)
}

fn main() -> ExitCode {
    // `cargo bench` appends --bench to the arguments it passes through.
    let args: Vec<String> = env::args().skip(1).filter(|arg| arg != "--bench").collect();
    if let [mode, case, n] = args.as_slice() {
        if mode == "run" {
            run(case, n.parse().expect("n is a number"));
            return ExitCode::SUCCESS;
        }
    }
    match gate(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(err) => {
            eprintln!("perf_ir: {err}");
            ExitCode::from(2)
        }
    }
}
