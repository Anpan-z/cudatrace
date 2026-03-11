use std::collections::HashSet;
use std::env;
use std::sync::LazyLock;

const ENV_OUTPUT: &str = "LIB_CUDATRACE_OUTPUT";
const ENV_PATH: &str = "LIB_CUDATRACE_PATH";
const ENV_TRACE: &str = "LIB_CUDATRACE_TRACE";
const ENV_IOCTL_DECODE: &str = "LIB_CUDATRACE_IOCTL_DECODE";
const ENV_MAX_BLOB: &str = "LIB_CUDATRACE_MAX_BLOB";
const ENV_DEREF: &str = "LIB_CUDATRACE_DEREF";
const ENV_MAX_DEREF_DEPTH: &str = "LIB_CUDATRACE_MAX_DEREF_DEPTH";
const ENV_MAX_DEREF_BYTES: &str = "LIB_CUDATRACE_MAX_DEREF_BYTES";
const ENV_HEXDUMP_LEN: &str = "LIB_CUDATRACE_HEXDUMP_LEN";
const ENV_TIME_UNIT: &str = "LIB_CUDATRACE_TIME_UNIT";
const ENV_LEFT_META: &str = "LIB_CUDATRACE_LEFT_META";
const ENV_FGRAPH_FUNCS: &str = "LIB_CUDATRACE_FGRAPH_FUNCS";
const ENV_FGRAPH_BUFFER_KB: &str = "LIB_CUDATRACE_FGRAPH_BUFFER_KB";

const DEFAULT_PATH: &str = "./cudatrace.output";
const DEFAULT_MAX_BLOB: usize = 256;
const MAX_BLOB_CAP: usize = 64 * 1024;
const DEFAULT_DEREF_ENABLED: bool = true;
const DEFAULT_MAX_DEREF_DEPTH: usize = 2;
const DEFAULT_MAX_DEREF_BYTES: usize = 1024;
const MAX_DEREF_BYTES_CAP: usize = 64 * 1024;
const DEFAULT_HEXDUMP_LEN: usize = 64;
const MAX_HEXDUMP_LEN_CAP: usize = 4096;
const DEFAULT_FGRAPH_BUFFER_KB: usize = 16 * 1024;
const MIN_FGRAPH_BUFFER_KB: usize = 64;
const MAX_FGRAPH_BUFFER_KB: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    File,
    Stdout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoctlDecodeMode {
    Full,
    Header,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeUnit {
    Us,
    Ns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftMetaMode {
    Off,
    Tid,
    Timestamp,
    TidTimestamp,
}

impl LeftMetaMode {
    pub const fn include_tid(self) -> bool {
        matches!(self, Self::Tid | Self::TidTimestamp)
    }

    pub const fn include_timestamp(self) -> bool {
        matches!(self, Self::Timestamp | Self::TidTimestamp)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceDomain {
    Cudart,
    Driver,
    Syscall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceMask {
    pub cudart: bool,
    pub driver: bool,
    pub syscall: bool,
}

impl TraceMask {
    pub const fn all() -> Self {
        Self {
            cudart: true,
            driver: true,
            syscall: true,
        }
    }

    fn any_enabled(&self) -> bool {
        self.cudart || self.driver || self.syscall
    }

    pub const fn enabled_for(&self, domain: TraceDomain) -> bool {
        match domain {
            TraceDomain::Cudart => self.cudart,
            TraceDomain::Driver => self.driver,
            TraceDomain::Syscall => self.syscall,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerefConfig {
    pub enabled: bool,
    pub max_depth: usize,
    pub max_bytes: usize,
    pub hexdump_len: usize,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub output: OutputMode,
    pub path: String,
    pub trace: TraceMask,
    pub ioctl_decode: IoctlDecodeMode,
    pub max_blob: usize,
    pub deref: DerefConfig,
    pub time_unit: TimeUnit,
    pub left_meta: LeftMetaMode,
    pub fgraph_funcs: HashSet<String>,
    pub fgraph_buffer_kb: usize,
}

pub static CONFIG: LazyLock<Config> = LazyLock::new(Config::from_process_env);

pub fn global() -> &'static Config {
    &CONFIG
}

impl Config {
    pub fn from_process_env() -> Self {
        Self::from_lookup(|key| env::var(key).ok())
    }

    pub fn trace_enabled(&self, domain: TraceDomain) -> bool {
        self.trace.enabled_for(domain)
    }

    pub fn fgraph_enabled(&self) -> bool {
        !self.fgraph_funcs.is_empty()
    }

    pub fn fgraph_match(&self, func: &str) -> bool {
        self.fgraph_funcs.contains(func)
    }

    fn from_lookup<F>(lookup: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let output = parse_output(lookup(ENV_OUTPUT).as_deref());
        let path = lookup(ENV_PATH)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_PATH.to_owned());
        let trace = parse_trace(lookup(ENV_TRACE).as_deref());
        let ioctl_decode = parse_ioctl_decode(lookup(ENV_IOCTL_DECODE).as_deref());
        let max_blob = parse_max_blob(lookup(ENV_MAX_BLOB).as_deref());
        let deref = parse_deref(
            lookup(ENV_DEREF).as_deref(),
            lookup(ENV_MAX_DEREF_DEPTH).as_deref(),
            lookup(ENV_MAX_DEREF_BYTES).as_deref(),
            lookup(ENV_HEXDUMP_LEN).as_deref(),
        );
        let time_unit = parse_time_unit(lookup(ENV_TIME_UNIT).as_deref());
        let left_meta = parse_left_meta(lookup(ENV_LEFT_META).as_deref());
        let fgraph_funcs = parse_fgraph_funcs(lookup(ENV_FGRAPH_FUNCS).as_deref());
        let fgraph_buffer_kb = parse_fgraph_buffer_kb(lookup(ENV_FGRAPH_BUFFER_KB).as_deref());

        Self {
            output,
            path,
            trace,
            ioctl_decode,
            max_blob,
            deref,
            time_unit,
            left_meta,
            fgraph_funcs,
            fgraph_buffer_kb,
        }
    }
}

fn parse_output(value: Option<&str>) -> OutputMode {
    match value.map(normalize) {
        Some(v) if v == "stdout" => OutputMode::Stdout,
        _ => OutputMode::File,
    }
}

fn parse_trace(value: Option<&str>) -> TraceMask {
    let Some(raw) = value.map(normalize) else {
        return TraceMask::all();
    };

    if raw == "all" {
        return TraceMask::all();
    }

    let mut mask = TraceMask {
        cudart: false,
        driver: false,
        syscall: false,
    };

    for token in raw.split(',') {
        match token.trim() {
            "cudart" => mask.cudart = true,
            "driver" => mask.driver = true,
            "syscall" => mask.syscall = true,
            _ => {}
        }
    }

    if mask.any_enabled() {
        mask
    } else {
        TraceMask::all()
    }
}

fn parse_ioctl_decode(value: Option<&str>) -> IoctlDecodeMode {
    match value.map(normalize) {
        Some(v) if v == "header" => IoctlDecodeMode::Header,
        Some(v) if v == "off" => IoctlDecodeMode::Off,
        _ => IoctlDecodeMode::Full,
    }
}

fn parse_max_blob(value: Option<&str>) -> usize {
    let parsed = value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MAX_BLOB);

    parsed.min(MAX_BLOB_CAP)
}

fn parse_deref(
    enabled: Option<&str>,
    depth: Option<&str>,
    max_bytes: Option<&str>,
    hexdump_len: Option<&str>,
) -> DerefConfig {
    let enabled = enabled
        .map(normalize)
        .map(|v| !matches!(v.as_str(), "0" | "off" | "false" | "no"))
        .unwrap_or(DEFAULT_DEREF_ENABLED);
    let max_depth = depth
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_DEREF_DEPTH)
        .min(8);
    let max_bytes = max_bytes
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MAX_DEREF_BYTES)
        .min(MAX_DEREF_BYTES_CAP);
    let hexdump_len = hexdump_len
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_HEXDUMP_LEN)
        .min(MAX_HEXDUMP_LEN_CAP);
    DerefConfig {
        enabled,
        max_depth,
        max_bytes,
        hexdump_len,
    }
}

fn parse_time_unit(value: Option<&str>) -> TimeUnit {
    match value.map(normalize) {
        Some(v) if v == "ns" => TimeUnit::Ns,
        _ => TimeUnit::Us,
    }
}

fn parse_left_meta(value: Option<&str>) -> LeftMetaMode {
    let Some(raw) = value.map(normalize) else {
        return LeftMetaMode::Off;
    };
    if raw.is_empty() || raw == "off" || raw == "0" || raw == "none" {
        return LeftMetaMode::Off;
    }
    if raw == "1" || raw == "on" || raw == "true" || raw == "yes" || raw == "all" {
        return LeftMetaMode::TidTimestamp;
    }

    let mut include_tid = false;
    let mut include_timestamp = false;
    for token in raw.split(|c: char| [',', '|', '+'].contains(&c)) {
        match token.trim() {
            "tid" | "thread" | "threadid" => include_tid = true,
            "ts" | "time" | "timestamp" => include_timestamp = true,
            _ => {}
        }
    }

    match (include_tid, include_timestamp) {
        (true, true) => LeftMetaMode::TidTimestamp,
        (true, false) => LeftMetaMode::Tid,
        (false, true) => LeftMetaMode::Timestamp,
        (false, false) => LeftMetaMode::Off,
    }
}

fn normalize(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

fn parse_fgraph_funcs(value: Option<&str>) -> HashSet<String> {
    let Some(raw) = value else {
        return HashSet::new();
    };
    let mut out = HashSet::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        out.insert(token.to_owned());
        // CUDA runtime may resolve cudaMallocHost calls via cudaHostAlloc wrappers.
        // Treat them as aliases for fgraph function-window matching.
        match token {
            "cudaMallocHost" => {
                out.insert("cudaHostAlloc".to_owned());
            }
            "cudaHostAlloc" => {
                out.insert("cudaMallocHost".to_owned());
            }
            _ => {}
        }
    }
    out
}

fn parse_fgraph_buffer_kb(value: Option<&str>) -> usize {
    let parsed = value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_FGRAPH_BUFFER_KB);
    parsed.clamp(MIN_FGRAPH_BUFFER_KB, MAX_FGRAPH_BUFFER_KB)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn parse_from_map(map: &HashMap<&str, &str>) -> Config {
        Config::from_lookup(|k| map.get(k).map(|v| (*v).to_owned()))
    }

    #[test]
    fn defaults_match_plan() {
        let map = HashMap::new();
        let cfg = parse_from_map(&map);

        assert_eq!(cfg.output, OutputMode::File);
        assert_eq!(cfg.path, "./cudatrace.output");
        assert_eq!(cfg.trace, TraceMask::all());
        assert_eq!(cfg.ioctl_decode, IoctlDecodeMode::Full);
        assert_eq!(cfg.max_blob, 256);
        assert_eq!(
            cfg.deref,
            DerefConfig {
                enabled: DEFAULT_DEREF_ENABLED,
                max_depth: DEFAULT_MAX_DEREF_DEPTH,
                max_bytes: DEFAULT_MAX_DEREF_BYTES,
                hexdump_len: DEFAULT_HEXDUMP_LEN
            }
        );
        assert_eq!(cfg.time_unit, TimeUnit::Us);
        assert_eq!(cfg.left_meta, LeftMetaMode::Off);
        assert!(cfg.fgraph_funcs.is_empty());
        assert_eq!(cfg.fgraph_buffer_kb, DEFAULT_FGRAPH_BUFFER_KB);
    }

    #[test]
    fn parse_trace_subset() {
        let mut map = HashMap::new();
        map.insert(ENV_TRACE, "driver,syscall");

        let cfg = parse_from_map(&map);
        assert!(!cfg.trace.cudart);
        assert!(cfg.trace.driver);
        assert!(cfg.trace.syscall);
    }

    #[test]
    fn invalid_values_fallback_to_defaults() {
        let mut map = HashMap::new();
        map.insert(ENV_OUTPUT, "unknown");
        map.insert(ENV_TRACE, "x,y");
        map.insert(ENV_IOCTL_DECODE, "bad");
        map.insert(ENV_MAX_BLOB, "-1");
        map.insert(ENV_TIME_UNIT, "bad");
        map.insert(ENV_LEFT_META, "bad");

        let cfg = parse_from_map(&map);
        assert_eq!(cfg.output, OutputMode::File);
        assert_eq!(cfg.trace, TraceMask::all());
        assert_eq!(cfg.ioctl_decode, IoctlDecodeMode::Full);
        assert_eq!(cfg.max_blob, 256);
        assert_eq!(
            cfg.deref,
            DerefConfig {
                enabled: DEFAULT_DEREF_ENABLED,
                max_depth: DEFAULT_MAX_DEREF_DEPTH,
                max_bytes: DEFAULT_MAX_DEREF_BYTES,
                hexdump_len: DEFAULT_HEXDUMP_LEN
            }
        );
        assert_eq!(cfg.time_unit, TimeUnit::Us);
        assert_eq!(cfg.left_meta, LeftMetaMode::Off);
        assert!(cfg.fgraph_funcs.is_empty());
        assert_eq!(cfg.fgraph_buffer_kb, DEFAULT_FGRAPH_BUFFER_KB);
    }

    #[test]
    fn parse_left_meta_variants() {
        let mut map = HashMap::new();
        map.insert(ENV_LEFT_META, "tid");
        assert_eq!(parse_from_map(&map).left_meta, LeftMetaMode::Tid);

        map.insert(ENV_LEFT_META, "timestamp");
        assert_eq!(parse_from_map(&map).left_meta, LeftMetaMode::Timestamp);

        map.insert(ENV_LEFT_META, "tid,ts");
        assert_eq!(parse_from_map(&map).left_meta, LeftMetaMode::TidTimestamp);

        map.insert(ENV_LEFT_META, "1");
        assert_eq!(parse_from_map(&map).left_meta, LeftMetaMode::TidTimestamp);

        map.insert(ENV_LEFT_META, "off");
        assert_eq!(parse_from_map(&map).left_meta, LeftMetaMode::Off);
    }

    #[test]
    fn parse_fgraph_funcs_list() {
        let mut map = HashMap::new();
        map.insert(ENV_FGRAPH_FUNCS, "cudaMalloc, cuInit , cudaMalloc,");

        let cfg = parse_from_map(&map);
        assert!(cfg.fgraph_enabled());
        assert!(cfg.fgraph_match("cudaMalloc"));
        assert!(cfg.fgraph_match("cuInit"));
        assert!(!cfg.fgraph_match("cudaFree"));
        assert_eq!(cfg.fgraph_funcs.len(), 2);
    }

    #[test]
    fn parse_fgraph_funcs_adds_cuda_host_alloc_aliases() {
        let mut map = HashMap::new();
        map.insert(ENV_FGRAPH_FUNCS, "cudaMallocHost");

        let cfg = parse_from_map(&map);
        assert!(cfg.fgraph_match("cudaMallocHost"));
        assert!(cfg.fgraph_match("cudaHostAlloc"));
    }

    #[test]
    fn parse_fgraph_buffer_kb_range() {
        let mut map = HashMap::new();

        map.insert(ENV_FGRAPH_BUFFER_KB, "32768");
        assert_eq!(parse_from_map(&map).fgraph_buffer_kb, 32768);

        map.insert(ENV_FGRAPH_BUFFER_KB, "0");
        assert_eq!(parse_from_map(&map).fgraph_buffer_kb, MIN_FGRAPH_BUFFER_KB);

        map.insert(ENV_FGRAPH_BUFFER_KB, "999999999");
        assert_eq!(parse_from_map(&map).fgraph_buffer_kb, MAX_FGRAPH_BUFFER_KB);
    }

    #[test]
    fn parse_deref_controls() {
        let mut map = HashMap::new();
        map.insert(ENV_DEREF, "off");
        map.insert(ENV_MAX_DEREF_DEPTH, "5");
        map.insert(ENV_MAX_DEREF_BYTES, "2048");
        map.insert(ENV_HEXDUMP_LEN, "96");

        let cfg = parse_from_map(&map);
        assert!(!cfg.deref.enabled);
        assert_eq!(cfg.deref.max_depth, 5);
        assert_eq!(cfg.deref.max_bytes, 2048);
        assert_eq!(cfg.deref.hexdump_len, 96);
    }
}
