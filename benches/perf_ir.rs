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
//!   at `n = N` and `n = 0`, where `N` is `N_OPS`, or `N_OPS_MIB` for a 1 MiB
//!   case. Ir/op is `(Ir[N] - Ir[0]) / N`, so process start, setup, the
//!   warm-up and exit cancel.
//! - Instruction counts miss the kernel's work, so for cases from `FAULTS_FROM`
//!   up the gate also runs `perf_ir faults <case> N_OPS` natively and records
//!   the minor page faults (`getrusage`) over those `N_OPS` calls, the cost of
//!   an allocator that hands a call fresh pages instead of reused ones.
//! - Budgets are keyed by architecture, OS and compiled-in CPU features in
//!   `perf_ir_baselines.json`. A case fails at `FAIL_PCT` over its budget and
//!   warns from `WARN_PCT`; a fault count fails at `FAIL_PCT` and at least one
//!   page per op over. `--update` ratchets budgets down to the measured
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
/// Iterations for a 1 MiB case. One call costs about 16 times a 64 KiB one,
/// and the CI job measures every case twice (base and head) inside a
/// 30-minute limit.
const N_OPS_MIB: u64 = 20;
/// Cases from this size up also count minor page faults, natively, over
/// `N_OPS` calls whatever their size: a native call is cheap, and a long
/// window keeps a few stray faults far from a page per call. Their buffers
/// are large enough for glibc's mmap and trim thresholds to decide whether a
/// call reuses memory or faults in fresh pages, and that work is the
/// kernel's, which instruction counts do not see.
const FAULTS_FROM: usize = 64 * 1024;
const FAIL_PCT: f64 = 1.0;
const WARN_PCT: f64 = 0.2;
const BASELINES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/benches/perf_ir_baselines.json"
);

const MIB: usize = 1024 * 1024;
/// A small value, a typical value, a large object (as `hot_path`).
const SIZES: &[usize] = &[64, 1024, 64 * 1024];
/// ByteStorage picks its strategy by size, so store and retrieve also measure
/// 40 B, under the literals-only block threshold (64 B), and 1 MiB. Its
/// large-payload switch compares the envelope (store) or the compressed
/// payload (retrieve) with 64 KiB: the 64 KiB payload stores as a
/// 24,702-byte envelope and never reaches it, the 1 MiB one as 383,893 bytes,
/// past glibc's default mmap threshold too.
const STORAGE_SIZES: &[usize] = &[40, 64, 1024, 64 * 1024, MIB];

/// Operations and their payload sizes. HKDF derives from the master key and
/// tenant id alone, so it has one case with no size.
const OPS: [(&str, &[usize]); 8] = [
    ("store", STORAGE_SIZES),
    ("retrieve", STORAGE_SIZES),
    ("prescan", SIZES),
    ("encrypt", SIZES),
    ("decrypt", SIZES),
    ("keyring_decrypt", SIZES),
    ("tenant_keyring_decrypt", SIZES),
    ("hkdf", &[]),
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
        .flat_map(|&(op, sizes)| {
            if sizes.is_empty() {
                vec![op.to_string()]
            } else {
                sizes.iter().map(|size| format!("{op}/{size}")).collect()
            }
        })
        .collect()
}

/// A case id's operation and payload size (0 for a case with no size).
fn parse_case(case: &str) -> (&str, usize) {
    match case.split_once('/') {
        Some((op, size)) => (op, size.parse().expect("case size is a number")),
        None => (case, 0),
    }
}

/// Calls in a case's measured run.
fn n_ops(case: &str) -> u64 {
    if parse_case(case).1 >= MIB {
        N_OPS_MIB
    } else {
        N_OPS
    }
}

fn counts_faults(case: &str) -> bool {
    parse_case(case).1 >= FAULTS_FROM
}

// ── measured process ────────────────────────────────────────────────────────

/// Build the fixtures and return the operation `case` measures. Setup runs in
/// both the `N` and the 0 run, so only what the closure does is counted.
fn operation(case: &str) -> Box<dyn FnMut() -> usize> {
    let (op, size) = parse_case(case);
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

/// Minor page faults over `n` calls, counted after setup, the warm-up call and
/// `n` uncounted calls. The first calls after the warm-up can still grow the
/// heap once, which is not a per-call cost: on glibc 2.39 the 1 MiB `store`
/// takes 98 faults on its second call and none after. `None` where
/// `getrusage` is not available.
fn faults(case: &str, n: u64) -> Option<u64> {
    let mut op = operation(case);
    for _ in 0..=n {
        black_box(op());
    }
    let before = minor_faults()?;
    for _ in 0..n {
        black_box(op());
    }
    Some(minor_faults()? - before)
}

/// This process's minor page faults so far: `getrusage(RUSAGE_SELF)`'s
/// `ru_minflt`.
#[cfg(all(unix, target_pointer_width = "64"))]
fn minor_faults() -> Option<u64> {
    use std::ffi::{c_int, c_long};
    extern "C" {
        fn getrusage(who: c_int, usage: *mut c_long) -> c_int;
    }
    const RUSAGE_SELF: c_int = 0;
    // On 64-bit Linux and macOS, struct rusage is two struct timevals of two
    // words each, then 14 longs: ru_maxrss, ru_ixrss, ru_idrss, ru_isrss,
    // ru_minflt, ... So ru_minflt is word 8 of its 18.
    const RU_MINFLT: usize = 8;
    let mut usage: [c_long; 32] = [0; 32];
    // SAFETY: getrusage writes one 18-word struct rusage, and the buffer holds 32.
    let status = unsafe { getrusage(RUSAGE_SELF, usage.as_mut_ptr()) };
    (status == 0).then(|| usage[RU_MINFLT] as u64)
}

#[cfg(not(all(unix, target_pointer_width = "64")))]
fn minor_faults() -> Option<u64> {
    None
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
    /// Minor page faults over `N_OPS` (1,000) calls, for cases from
    /// `FAULTS_FROM` up.
    #[serde(default)]
    faults_per_1000_ops: BTreeMap<String, u64>,
}

/// One case's figures from one gate run.
struct Measured {
    case: String,
    ir: u64,
    /// Minor page faults over `N_OPS` calls, for cases from `FAULTS_FROM` up.
    faults: Option<u64>,
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

/// Minor page faults over `n` calls of one `perf_ir faults` process, run
/// natively: under valgrind the count would include valgrind's own memory.
/// The environment is empty for the same reasons as in `total_ir`, and because
/// `MALLOC_*` variables and `GLIBC_TUNABLES` change the allocator's thresholds.
fn total_faults(exe: &Path, case: &str, n: u64) -> Result<u64, String> {
    let out = Command::new(exe)
        .args(["faults", case, &n.to_string()])
        .env_clear()
        .output()
        .map_err(|e| format!("{case} faults n={n}: cannot start: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("{case} faults n={n}: {}\n{stderr}", out.status));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .trim()
        .parse()
        .map_err(|e| format!("{case} faults n={n}: cannot read {stdout:?}: {e}"))
}

/// A process the gate runs: a case under cachegrind at `n` calls, or a case
/// run natively to count its page faults over `n` calls.
#[derive(Clone, Copy)]
enum Run<'a> {
    Ir(&'a str, u64),
    Faults(&'a str, u64),
}

/// Each case's figures, in case order. Runs are independent processes, so
/// they parallelise.
fn measure(valgrind: &Path, cases: &[String], jobs: usize) -> Result<Vec<Measured>, String> {
    let exe = env::current_exe().map_err(|e| format!("cannot locate this binary: {e}"))?;
    let runs: Vec<Run> = cases
        .iter()
        .flat_map(|case| {
            let n = n_ops(case);
            let mut runs = vec![Run::Ir(case, n), Run::Ir(case, 0)];
            if counts_faults(case) {
                runs.push(Run::Faults(case, N_OPS));
            }
            runs
        })
        .collect();
    let next = AtomicUsize::new(0);
    let counts: Vec<OnceLock<Result<u64, String>>> = runs.iter().map(|_| OnceLock::new()).collect();
    thread::scope(|scope| {
        for _ in 0..jobs.clamp(1, runs.len()) {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(&run) = runs.get(i) else { break };
                let _ = counts[i].set(match run {
                    Run::Ir(case, n) => total_ir(valgrind, &exe, case, n),
                    Run::Faults(case, n) => total_faults(&exe, case, n),
                });
            });
        }
    });
    let counts = counts
        .into_iter()
        .map(|count| count.into_inner().expect("every run was measured"))
        .collect::<Result<Vec<u64>, String>>()?;
    // Read the counts back in the order `runs` was built in.
    let mut counts = counts.into_iter();
    let mut next_count = || counts.next().expect("one count per run");
    cases
        .iter()
        .map(|case| {
            let n = n_ops(case);
            let (full, setup) = (next_count(), next_count());
            let ir = match full.checked_sub(setup) {
                Some(delta) if delta > 0 => (delta + n / 2) / n,
                _ => return Err(format!("{case}: Ir[{n}] {full} is not above Ir[0] {setup}")),
            };
            let faults = counts_faults(case).then(&mut next_count);
            Ok(Measured {
                case: case.clone(),
                ir,
                faults,
            })
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
fn compare(platform: &Platform, measured: &[Measured]) -> (Vec<String>, bool) {
    let mut ok = true;
    let mut lines = Vec::new();
    for Measured { case, ir, faults } in measured {
        let ir = *ir;
        lines.push(match platform.budgets.get(case) {
            None => {
                ok = false;
                format!(
                    "FAIL  {case:28} {:>10} Ir/op  no budget (run make perf-ir-update)",
                    thousands(ir)
                )
            }
            Some(&budget) => {
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
            }
        });
        let Some(faults) = *faults else { continue };
        let per_op = |count: u64| count as f64 / N_OPS as f64;
        lines.push(match platform.faults_per_1000_ops.get(case) {
            None => {
                ok = false;
                format!(
                    "FAIL  {case:28} {:>10.3} faults/op  no budget (run make perf-ir-update)",
                    per_op(faults)
                )
            }
            Some(&budget) => {
                // The regression this catches is a buffer the allocator no
                // longer reuses: whole pages on every call, each a trap and a
                // zeroed page that Ir does not count. So a count fails from
                // one page per call over (N_OPS faults) and FAIL_PCT, and
                // moves the verdict no other way: a busy host has added up
                // to 4 stray faults in 1,000 calls that quiet runs never take.
                let over_pct = |over: u64| over as f64 >= budget as f64 * FAIL_PCT / 100.0;
                let verdict = if faults >= budget + N_OPS && over_pct(faults - budget) {
                    ok = false;
                    "FAIL"
                } else if budget >= faults + N_OPS {
                    "LOWER"
                } else {
                    "ok"
                };
                format!(
                    "{verdict:5} {case:28} {:>10.3} faults/op  budget {:>10.3}",
                    per_op(faults),
                    per_op(budget)
                )
            }
        });
    }
    (lines, ok)
}

/// New budgets: only ever lower, unless the increase is deliberate.
fn ratchet(platform: &mut Platform, measured: &[Measured], allow_increase: bool) {
    let lower = |budgets: &mut BTreeMap<String, u64>, case: &String, value: u64| {
        let budget = budgets.entry(case.clone()).or_insert(value);
        if allow_increase || value < *budget {
            *budget = value;
        }
    };
    for Measured { case, ir, faults } in measured {
        lower(&mut platform.budgets, case, *ir);
        if let Some(faults) = *faults {
            lower(&mut platform.faults_per_1000_ops, case, faults);
        }
    }
}

const USAGE: &str = "\
usage: cargo bench --features encryption --bench perf_ir -- [options]
       (or make perf-ir / make perf-ir-update)

Measures Ir/op for each case under cachegrind, and minor page faults per op
natively for cases from 64 KiB up, and compares them with the budgets in
benches/perf_ir_baselines.json. Exit 0 pass, 1 regression, 2 error.

options:
  --case <id>        measure only this case (repeatable)
  --update           write lower measured figures back as budgets
  --allow-increase   with --update, also raise budgets
  --jobs <n>         processes at a time (default: min(8, cores))
  --baselines <path> read and write budgets here instead of the committed file

perf_ir run <case> <n>     the measured process: setup, one warm-up op, n ops
perf_ir faults <case> <n>  setup, n + 1 settling ops, then prints the minor
                           page faults n more ops take";

fn gate(args: &[String]) -> Result<bool, String> {
    let (mut update, mut allow_increase, mut cases) = (false, false, Vec::new());
    let mut path = PathBuf::from(BASELINES);
    let mut jobs = thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(8);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--update" => update = true,
            "--allow-increase" => allow_increase = true,
            "--case" => cases.push(args.next().ok_or("--case needs a case id")?.clone()),
            "--baselines" => path = args.next().ok_or("--baselines needs a path")?.into(),
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
    let shown = path.display();
    let text = fs::read_to_string(&path).map_err(|e| format!("{shown}: {e}"))?;
    let mut baselines: Baselines =
        serde_json::from_str(&text).map_err(|e| format!("{shown}: {e}"))?;
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
        "cachekit-core Ir/op on {key} (rustc {rustc}, {valgrind}): (Ir[N] - Ir[0]) / N, \
         N = {N_OPS} ({N_OPS_MIB} at 1 MiB); faults/op natively over {N_OPS} ops from 64 KiB"
    );
    // With --update, report against the budgets as written, so the only FAIL
    // left is a regression that --allow-increase did not accept.
    if update {
        ratchet(platform, &measured, allow_increase);
        platform.rustc = rustc;
        platform.valgrind = valgrind;
    }
    let (lines, ok) = compare(platform, &measured);
    println!("{}", lines.join("\n"));
    if update {
        baselines.method = format!(
            "cachegrind Ir per op, (Ir[N] - Ir[0]) / N with N = {N_OPS} ({N_OPS_MIB} at 1 MiB), \
             one process per case, empty environment; faults_per_1000_ops: minor page \
             faults (getrusage) over {N_OPS} ops, native, after {N_OPS} + 1 settling ops, \
             cases from 64 KiB; written by benches/perf_ir.rs --update"
        );
        let json = serde_json::to_string_pretty(&baselines).map_err(|e| e.to_string())?;
        fs::write(&path, json + "\n").map_err(|e| format!("{shown}: {e}"))?;
        println!("budgets written to {shown}");
    }
    println!(
        "{}",
        match (ok, update) {
            (true, _) => "PASS",
            (false, false) =>
                "FAIL: a case regressed by 1% or more (faults: and by a page per op), or has no budget",
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
        match mode.as_str() {
            "run" => {
                run(case, n.parse().expect("n is a number"));
                return ExitCode::SUCCESS;
            }
            "faults" => {
                let Some(count) = faults(case, n.parse().expect("n is a number")) else {
                    eprintln!("perf_ir: getrusage is not available on this target");
                    return ExitCode::from(2);
                };
                println!("{count}");
                return ExitCode::SUCCESS;
            }
            _ => {}
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
