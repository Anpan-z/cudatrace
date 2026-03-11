use crate::config::{OutputMode, TimeUnit, global};
use crate::decode::ioctl::{set_decode_target_pid, summarize_ioctl};
use crate::dlsym::resolve_next_from_ptr;
use crate::line_meta::{current_tid, now_timestamp_for_config, prepend_left_meta};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::CString;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Once;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

type pid_t = i32;

const PTRACE_ATTACH: i32 = 16;
const PTRACE_GETREGS: i32 = 12;
const PTRACE_SETOPTIONS: i32 = 0x4200;
const PTRACE_GETEVENTMSG: i32 = 0x4201;
const PTRACE_SYSCALL: i32 = 24;

const PTRACE_O_TRACESYSGOOD: u64 = 0x00000001;
const PTRACE_O_TRACEFORK: u64 = 0x00000002;
const PTRACE_O_TRACEVFORK: u64 = 0x00000004;
const PTRACE_O_TRACECLONE: u64 = 0x00000008;
const PTRACE_O_TRACEEXEC: u64 = 0x00000010;
const PTRACE_O_TRACEEXIT: u64 = 0x00000040;

const PTRACE_EVENT_FORK: i32 = 1;
const PTRACE_EVENT_VFORK: i32 = 2;
const PTRACE_EVENT_CLONE: i32 = 3;
const PTRACE_EVENT_EXEC: i32 = 4;

const SIGTRAP: i32 = 5;
const SYSCALL_STOP_SIG: i32 = SIGTRAP | 0x80;

const PR_SET_PTRACER: i32 = 0x5961_6d61;
const PR_SET_PTRACER_ANY: i64 = -1;

const WAIT_ALL_THREADS: i32 = 0x4000_0000;
const EINTR: i32 = 4;
const EAGAIN: i32 = 11;
const EWOULDBLOCK: i32 = 11;
const EBADF: i32 = 9;
const EPIPE: i32 = 32;
const ECHILD: i32 = 10;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 0o4000;
const O_CREAT_MASK: u64 = crate::ffi::O_CREAT as u64;
const O_ACCMODE_MASK: u64 = 0o3;
const O_WRONLY_MASK: u64 = 0o1;
const O_RDWR_MASK: u64 = 0o2;
const O_EXCL_MASK: u64 = 0o200;
const O_NOCTTY_MASK: u64 = 0o400;
const O_TRUNC_MASK: u64 = 0o1000;
const O_APPEND_MASK: u64 = crate::ffi::O_APPEND as u64;
const O_DSYNC_MASK: u64 = 0o10000;
const O_DIRECT_MASK: u64 = 0o40000;
const O_LARGEFILE_MASK: u64 = 0o100000;
const O_DIRECTORY_MASK: u64 = 0o200000;
const O_NOFOLLOW_MASK: u64 = 0o400000;
const O_NOATIME_MASK: u64 = 0o1000000;
const O_CLOEXEC_MASK: u64 = crate::ffi::O_CLOEXEC as u64;
const O_SYNC_MASK: u64 = 0o4010000;
const O_PATH_MASK: u64 = 0o10000000;
const O_TMPFILE_MASK: u64 = 0o20200000;

const PROT_NONE_MASK: u64 = 0x0;
const PROT_READ_MASK: u64 = 0x1;
const PROT_WRITE_MASK: u64 = 0x2;
const PROT_EXEC_MASK: u64 = 0x4;
const PROT_SEM_MASK: u64 = 0x8;
const PROT_GROWSDOWN_MASK: u64 = 0x0100_0000;
const PROT_GROWSUP_MASK: u64 = 0x0200_0000;

const MAP_TYPE_MASK: u64 = 0x0f;
const MAP_SHARED_MASK: u64 = 0x01;
const MAP_PRIVATE_MASK: u64 = 0x02;
const MAP_SHARED_VALIDATE_MASK: u64 = 0x03;
const MAP_FIXED_MASK: u64 = 0x10;
const MAP_ANONYMOUS_MASK: u64 = 0x20;
const MAP_32BIT_MASK: u64 = 0x40;
const MAP_GROWSDOWN_MASK: u64 = 0x0100;
const MAP_DENYWRITE_MASK: u64 = 0x0800;
const MAP_EXECUTABLE_MASK: u64 = 0x1000;
const MAP_LOCKED_MASK: u64 = 0x2000;
const MAP_NORESERVE_MASK: u64 = 0x4000;
const MAP_POPULATE_MASK: u64 = 0x8000;
const MAP_NONBLOCK_MASK: u64 = 0x1_0000;
const MAP_STACK_MASK: u64 = 0x2_0000;
const MAP_HUGETLB_MASK: u64 = 0x4_0000;
const MAP_SYNC_MASK: u64 = 0x8_0000;
const MAP_FIXED_NOREPLACE_MASK: u64 = 0x10_0000;

const F_OK_MASK: u64 = 0x0;
const X_OK_MASK: u64 = 0x1;
const W_OK_MASK: u64 = 0x2;
const R_OK_MASK: u64 = 0x4;

const AT_SYMLINK_NOFOLLOW_MASK: u64 = 0x100;
const AT_EACCESS_MASK: u64 = 0x200;
const AT_NO_AUTOMOUNT_MASK: u64 = 0x800;
const AT_EMPTY_PATH_MASK: u64 = 0x1000;

const SEEK_SET: u64 = 0;
const SEEK_CUR: u64 = 1;
const SEEK_END: u64 = 2;
const SEEK_DATA: u64 = 3;
const SEEK_HOLE: u64 = 4;

const SYS_READ: i64 = 0;
const SYS_WRITE: i64 = 1;
const SYS_OPEN: i64 = 2;
const SYS_CLOSE: i64 = 3;
const SYS_STAT: i64 = 4;
const SYS_FSTAT: i64 = 5;
const SYS_LSTAT: i64 = 6;
const SYS_POLL: i64 = 7;
const SYS_LSEEK: i64 = 8;
const SYS_MMAP: i64 = 9;
const SYS_MUNMAP: i64 = 11;
const SYS_IOCTL: i64 = 16;
const SYS_PREAD64: i64 = 17;
const SYS_PWRITE64: i64 = 18;
const SYS_ACCESS: i64 = 21;
const SYS_SELECT: i64 = 23;
const SYS_DUP: i64 = 32;
const SYS_DUP2: i64 = 33;
const SYS_PRCTL: i64 = 157;
const SYS_FUTEX: i64 = 202;
const SYS_OPENAT: i64 = 257;
const SYS_NEWFSTATAT: i64 = 262;
const SYS_PPOLL: i64 = 271;
const SYS_PSELECT6: i64 = 270;
const SYS_FACCESSAT: i64 = 269;
const SYS_DUP3: i64 = 292;
const FGRAPH_WINDOW_EVENT_EXIT: u8 = 0;
const FGRAPH_WINDOW_EVENT_ENTER: u8 = 1;
const FGRAPH_FUNC_NAME_MAX: usize = 96;

static START: Once = Once::new();
static IN_TRACER_PROCESS: AtomicBool = AtomicBool::new(false);
static DEPTH_PIPE_WR_FD: AtomicI32 = AtomicI32::new(-1);
static FGRAPH_WINDOW_PIPE_WR_FD: AtomicI32 = AtomicI32::new(-1);

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserRegsStruct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
}

#[derive(Clone)]
struct SyscallState {
    active: bool,
    internal: bool,
    nr: i64,
    args: [u64; 6],
    path_hint: Option<String>,
    started_ts: u128,
    started_at: Instant,
    started_ts_us: u128,
    fgraph_waiting: bool,
    fgraph_capturing: bool,
}

impl Default for SyscallState {
    fn default() -> Self {
        Self {
            active: false,
            internal: false,
            nr: -1,
            args: [0; 6],
            path_hint: None,
            started_ts: 0,
            started_at: Instant::now(),
            started_ts_us: 0,
            fgraph_waiting: false,
            fgraph_capturing: false,
        }
    }
}

struct FusedWriter {
    output: OutputMode,
    base_path: String,
    fds: HashMap<pid_t, i32>,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DepthUpdate {
    tid: i32,
    depth: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FgraphWindowUpdate {
    tid: i32,
    depth: u32,
    seq: u32,
    event: u8,
    _reserved: [u8; 3],
    func: [u8; FGRAPH_FUNC_NAME_MAX],
}

impl Default for FgraphWindowUpdate {
    fn default() -> Self {
        Self {
            tid: 0,
            depth: 0,
            seq: 0,
            event: FGRAPH_WINDOW_EVENT_EXIT,
            _reserved: [0; 3],
            func: [0; FGRAPH_FUNC_NAME_MAX],
        }
    }
}

impl FgraphWindowUpdate {
    fn set_func(&mut self, func: &str) {
        self.func.fill(0);
        let src = func.as_bytes();
        let copy_len = src.len().min(self.func.len());
        self.func[..copy_len].copy_from_slice(&src[..copy_len]);
    }

    fn func_name(&self) -> String {
        let len = self
            .func
            .iter()
            .position(|&value| value == 0)
            .unwrap_or(self.func.len());
        String::from_utf8_lossy(&self.func[..len]).into_owned()
    }
}

#[derive(Clone)]
struct FgraphScopeLabel {
    func: String,
    seq: u32,
}

#[derive(Default)]
struct FgraphWindowState {
    depth: usize,
    labels: Vec<FgraphScopeLabel>,
}

#[derive(Clone)]
struct ActiveFgraphCapture {
    tid: pid_t,
    syscall_name: String,
    graph_function: Option<String>,
    syscall_enter: String,
    entry_ts_us: u128,
    scope_label: String,
}

impl FusedWriter {
    fn from_config() -> Self {
        let cfg = global();
        Self {
            output: cfg.output,
            base_path: cfg.path.clone(),
            fds: HashMap::new(),
        }
    }

    fn write_line(&mut self, tid: pid_t, line: &str) {
        let mut bytes = Vec::with_capacity(line.len() + 1);
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');

        match self.output {
            OutputMode::Stdout => {
                let _ = write_all(crate::ffi::STDOUT_FILENO, &bytes);
            }
            OutputMode::File => {
                if let Some(fd) = self.fd_for_tid(tid) {
                    if write_all(fd, &bytes).is_err() {
                        let _ = write_all(crate::ffi::STDOUT_FILENO, &bytes);
                    }
                } else {
                    let _ = write_all(crate::ffi::STDOUT_FILENO, &bytes);
                }
            }
        }
    }

    fn close_tid(&mut self, tid: pid_t) {
        if let Some(fd) = self.fds.remove(&tid) {
            let _ = call_real_close(fd);
        }
    }

    fn fd_for_tid(&mut self, tid: pid_t) -> Option<i32> {
        if let Some(fd) = self.fds.get(&tid).copied() {
            return Some(fd);
        }

        let path = format!("{}.tid-{}", self.base_path, tid);
        let path_c = CString::new(path.as_bytes()).ok()?;
        let fd = call_real_openat(
            crate::ffi::AT_FDCWD,
            path_c.as_ptr(),
            crate::ffi::O_CREAT
                | crate::ffi::O_WRONLY
                | crate::ffi::O_APPEND
                | crate::ffi::O_CLOEXEC,
            0o644,
        );
        if fd < 0 {
            None
        } else {
            self.fds.insert(tid, fd);
            Some(fd)
        }
    }
}

impl Drop for FusedWriter {
    fn drop(&mut self) {
        let fds = std::mem::take(&mut self.fds);
        for fd in fds.into_values() {
            let _ = call_real_close(fd);
        }
    }
}

unsafe extern "C" {
    #[link_name = "ptrace"]
    fn libc_ptrace(
        request: i32,
        pid: pid_t,
        addr: *mut crate::ffi::c_void,
        data: *mut crate::ffi::c_void,
    ) -> i64;
    fn pipe(fds: *mut i32) -> i32;
    fn fork() -> pid_t;
    fn getppid() -> pid_t;
    fn waitpid(pid: pid_t, status: *mut i32, options: i32) -> pid_t;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn _exit(status: i32) -> !;
}

type ReadFn = unsafe extern "C" fn(i32, *mut crate::ffi::c_void, usize) -> isize;
type WriteFn = unsafe extern "C" fn(i32, *const crate::ffi::c_void, usize) -> isize;
type CloseFn = unsafe extern "C" fn(i32) -> i32;
type OpenAtFn = unsafe extern "C" fn(i32, *const crate::ffi::c_char, i32, u32) -> i32;
type PrctlFn = unsafe extern "C" fn(i32, i64, i64, i64, i64) -> i32;

fn real_read() -> Option<ReadFn> {
    static REAL: OnceLock<Option<ReadFn>> = OnceLock::new();
    *REAL.get_or_init(|| unsafe { resolve_next_from_ptr::<ReadFn>(c"read".as_ptr()) })
}

fn real_write() -> Option<WriteFn> {
    static REAL: OnceLock<Option<WriteFn>> = OnceLock::new();
    *REAL.get_or_init(|| unsafe { resolve_next_from_ptr::<WriteFn>(c"write".as_ptr()) })
}

fn real_close() -> Option<CloseFn> {
    static REAL: OnceLock<Option<CloseFn>> = OnceLock::new();
    *REAL.get_or_init(|| unsafe { resolve_next_from_ptr::<CloseFn>(c"close".as_ptr()) })
}

fn real_openat() -> Option<OpenAtFn> {
    static REAL: OnceLock<Option<OpenAtFn>> = OnceLock::new();
    *REAL.get_or_init(|| unsafe { resolve_next_from_ptr::<OpenAtFn>(c"openat".as_ptr()) })
}

fn real_prctl() -> Option<PrctlFn> {
    static REAL: OnceLock<Option<PrctlFn>> = OnceLock::new();
    *REAL.get_or_init(|| unsafe { resolve_next_from_ptr::<PrctlFn>(c"prctl".as_ptr()) })
}

fn call_real_read(fd: i32, buf: *mut crate::ffi::c_void, count: usize) -> isize {
    if let Some(real) = real_read() {
        // SAFETY: caller upholds libc read ABI for fd/buf/count.
        unsafe { real(fd, buf, count) }
    } else {
        -1
    }
}

fn call_real_write(fd: i32, buf: *const crate::ffi::c_void, count: usize) -> isize {
    if let Some(real) = real_write() {
        // SAFETY: caller upholds libc write ABI for fd/buf/count.
        unsafe { real(fd, buf, count) }
    } else {
        -1
    }
}

fn call_real_close(fd: i32) -> i32 {
    if let Some(real) = real_close() {
        // SAFETY: caller upholds libc close ABI for fd.
        unsafe { real(fd) }
    } else {
        -1
    }
}

fn call_real_openat(dirfd: i32, path: *const crate::ffi::c_char, flags: i32, mode: u32) -> i32 {
    if let Some(real) = real_openat() {
        // SAFETY: caller upholds libc openat ABI for arguments.
        unsafe { real(dirfd, path, flags, mode) }
    } else {
        -1
    }
}

fn call_real_prctl(option: i32, arg2: i64, arg3: i64, arg4: i64, arg5: i64) -> i32 {
    if let Some(real) = real_prctl() {
        // SAFETY: caller upholds libc prctl ABI for arguments.
        unsafe { real(option, arg2, arg3, arg4, arg5) }
    } else {
        -1
    }
}

pub fn is_internal_tracer() -> bool {
    IN_TRACER_PROCESS.load(Ordering::Relaxed)
}

pub fn publish_graph_depth(depth: usize) {
    if is_internal_tracer() || !global().trace.syscall {
        return;
    }

    let fd = DEPTH_PIPE_WR_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }

    let msg = DepthUpdate {
        tid: current_tid(),
        depth: depth.min(u32::MAX as usize) as u32,
    };
    let bytes = depth_update_as_bytes(&msg);
    let written = call_real_write(fd, bytes.as_ptr().cast::<crate::ffi::c_void>(), bytes.len());
    if written == bytes.len() as isize {
        return;
    }
    if written < 0 {
        let err = last_errno();
        if err == EBADF || err == EPIPE {
            if DEPTH_PIPE_WR_FD
                .compare_exchange(fd, -1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                let _ = call_real_close(fd);
            }
        }
    }
}

pub fn publish_fgraph_window_enter(depth: usize, func: &str, seq: u32) {
    let mut msg = FgraphWindowUpdate {
        tid: current_tid(),
        depth: depth.min(u32::MAX as usize) as u32,
        seq,
        event: FGRAPH_WINDOW_EVENT_ENTER,
        ..Default::default()
    };
    msg.set_func(func);
    publish_fgraph_window_update(&msg);
}

pub fn publish_fgraph_window_exit(depth: usize) {
    let msg = FgraphWindowUpdate {
        tid: current_tid(),
        depth: depth.min(u32::MAX as usize) as u32,
        seq: 0,
        event: FGRAPH_WINDOW_EVENT_EXIT,
        ..Default::default()
    };
    publish_fgraph_window_update(&msg);
}

fn publish_fgraph_window_update(msg: &FgraphWindowUpdate) {
    if is_internal_tracer() || !global().trace.syscall || !global().fgraph_enabled() {
        return;
    }

    let fd = FGRAPH_WINDOW_PIPE_WR_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }

    let bytes = fgraph_window_update_as_bytes(msg);
    let written = call_real_write(fd, bytes.as_ptr().cast::<crate::ffi::c_void>(), bytes.len());
    if written == bytes.len() as isize {
        return;
    }
    if written < 0 {
        let err = last_errno();
        if err == EBADF || err == EPIPE {
            if FGRAPH_WINDOW_PIPE_WR_FD
                .compare_exchange(fd, -1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                let _ = call_real_close(fd);
            }
        }
    }
}

pub fn ensure_started() {
    if is_internal_tracer() {
        return;
    }
    START.call_once(|| {
        let cfg = global();
        if cfg.fgraph_enabled() && !cfg.trace.syscall {
            fatal_exit(
                "LIB_CUDATRACE_FGRAPH_FUNCS requires syscall tracing; include `syscall` in LIB_CUDATRACE_TRACE",
            );
        }
        if cfg.fgraph_enabled() {
            match crate::hook::fgraph::preflight() {
                Ok(()) => {}
                Err(err) => {
                    fatal_exit(&format!(
                        "LIB_CUDATRACE_FGRAPH_FUNCS is set but tracefs function_graph is unavailable: {err}"
                    ));
                }
            }
        }
        if !cfg.trace.syscall {
            debug_log("ptrace disabled by config");
            return;
        }
        debug_log("ptrace bootstrap start");
        // SAFETY: ptrace bootstrap is isolated in tracer child and synchronized by a pipe.
        unsafe {
            spawn_ptrace_tracer();
        }
    });
}

unsafe fn spawn_ptrace_tracer() {
    // SAFETY: allows descendant tracer process to attach current process under Yama.
    let _ = call_real_prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

    let mut fds = [0_i32; 2];
    // SAFETY: fds points to two valid ints.
    if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
        debug_log_errno("pipe failed");
        return;
    }
    let mut depth_fds = [0_i32; 2];
    // SAFETY: depth_fds points to two valid ints.
    if unsafe { pipe(depth_fds.as_mut_ptr()) } != 0 {
        debug_log_errno("depth pipe failed");
        let _ = call_real_close(fds[0]);
        let _ = call_real_close(fds[1]);
        return;
    }
    let mut fgraph_window_fds = [0_i32; 2];
    // SAFETY: fgraph_window_fds points to two valid ints.
    if unsafe { pipe(fgraph_window_fds.as_mut_ptr()) } != 0 {
        debug_log_errno("fgraph window pipe failed");
        let _ = call_real_close(fds[0]);
        let _ = call_real_close(fds[1]);
        let _ = call_real_close(depth_fds[0]);
        let _ = call_real_close(depth_fds[1]);
        return;
    }

    // SAFETY: fork creates tracer child for ptrace loop.
    let child = unsafe { fork() };
    if child < 0 {
        debug_log_errno("fork failed");
        let _ = call_real_close(fds[0]);
        let _ = call_real_close(fds[1]);
        let _ = call_real_close(depth_fds[0]);
        let _ = call_real_close(depth_fds[1]);
        let _ = call_real_close(fgraph_window_fds[0]);
        let _ = call_real_close(fgraph_window_fds[1]);
        return;
    }

    if child == 0 {
        IN_TRACER_PROCESS.store(true, Ordering::Relaxed);
        debug_log("ptrace child started");
        let _ = call_real_close(fds[0]);
        let _ = call_real_close(depth_fds[1]);
        let _ = call_real_close(fgraph_window_fds[1]);

        // SAFETY: getppid has no preconditions.
        let target = unsafe { getppid() };
        debug_log(&format!("ptrace child attach target={target}"));
        // SAFETY: child owns tracer loop and exits independently.
        unsafe {
            run_ptrace_loop(
                target,
                fds[1],
                fds[0],
                depth_fds[0],
                depth_fds[1],
                fgraph_window_fds[0],
                fgraph_window_fds[1],
            )
        };
        // SAFETY: hard exit to avoid returning into traced parent flow.
        unsafe { _exit(0) };
    }

    let _ = call_real_close(fds[1]);
    let _ = call_real_close(depth_fds[0]);
    let _ = call_real_close(fgraph_window_fds[0]);
    let _ = set_nonblocking(depth_fds[1]);
    let _ = set_nonblocking(fgraph_window_fds[1]);
    DEPTH_PIPE_WR_FD.store(depth_fds[1], Ordering::Relaxed);
    FGRAPH_WINDOW_PIPE_WR_FD.store(fgraph_window_fds[1], Ordering::Relaxed);

    let mut ready = [0_u8; 1];
    // SAFETY: reading one byte handshake from tracer child.
    let n = call_real_read(fds[0], ready.as_mut_ptr().cast::<crate::ffi::c_void>(), 1);
    if n == 1 && ready[0] == b'1' {
        debug_log("ptrace child ready");
    } else {
        debug_log("ptrace child not ready");
        let depth_fd = DEPTH_PIPE_WR_FD.swap(-1, Ordering::Relaxed);
        if depth_fd >= 0 {
            let _ = call_real_close(depth_fd);
        }
        let fgraph_fd = FGRAPH_WINDOW_PIPE_WR_FD.swap(-1, Ordering::Relaxed);
        if fgraph_fd >= 0 {
            let _ = call_real_close(fgraph_fd);
        }
        if global().fgraph_enabled() {
            fatal_exit("function_graph tracing requested but ptrace tracer failed to initialize");
        }
    }
    let _ = call_real_close(fds[0]);
}

unsafe fn run_ptrace_loop(
    target: pid_t,
    ready_fd: i32,
    bootstrap_hidden_fd: i32,
    depth_read_fd: i32,
    depth_hidden_fd: i32,
    fgraph_window_read_fd: i32,
    fgraph_window_hidden_fd: i32,
) {
    if ptrace_attach(target).is_err() {
        debug_log_errno("ptrace attach failed");
        signal_ready(ready_fd, false);
        return;
    }
    if wait_for_stop(target).is_err() {
        debug_log_errno("wait for attach-stop failed");
        signal_ready(ready_fd, false);
        return;
    }
    if set_ptrace_options(target).is_err() {
        debug_log_errno("set ptrace options failed");
        signal_ready(ready_fd, false);
        return;
    }
    if ptrace_syscall(target, 0).is_err() {
        debug_log_errno("resume ptrace syscall failed");
        signal_ready(ready_fd, false);
        return;
    }

    let mut fgraph_controller = if global().fgraph_enabled() {
        match crate::hook::fgraph::TraceFsController::init_or_fail() {
            Ok(controller) => Some(controller),
            Err(err) => {
                debug_log(&format!("fgraph init failed: {err}"));
                signal_ready(ready_fd, false);
                return;
            }
        }
    } else {
        None
    };

    signal_ready(ready_fd, true);
    let _ = call_real_close(ready_fd);

    let _ = set_nonblocking(depth_read_fd);
    let _ = set_nonblocking(fgraph_window_read_fd);

    let mut states: HashMap<pid_t, SyscallState> = HashMap::new();
    let mut depth_by_tid: HashMap<pid_t, usize> = HashMap::new();
    let mut fgraph_window_by_tid: HashMap<pid_t, FgraphWindowState> = HashMap::new();
    let mut active_fgraph_capture: Option<ActiveFgraphCapture> = None;
    let mut waiting_fgraph_tids: VecDeque<pid_t> = VecDeque::new();
    let mut fd_paths: HashMap<i32, String> = HashMap::new();
    let mut hidden_fds: HashSet<i32> = HashSet::new();
    if bootstrap_hidden_fd >= 0 {
        hidden_fds.insert(bootstrap_hidden_fd);
    }
    if depth_hidden_fd >= 0 {
        hidden_fds.insert(depth_hidden_fd);
    }
    if fgraph_window_hidden_fd >= 0 {
        hidden_fds.insert(fgraph_window_hidden_fd);
    }
    seed_fd_state_from_proc(target, &mut fd_paths, &mut hidden_fds);
    let mut cudatrace_ranges = load_cudatrace_ranges(target);
    if debug_enabled() {
        debug_log(&format!(
            "loaded {} cudatrace map range(s) for pid={target}",
            cudatrace_ranges.len()
        ));
    }
    let mut writer = FusedWriter::from_config();

    loop {
        let mut status = 0_i32;
        // SAFETY: wait for any traced thread in this process tree.
        let pid = unsafe { waitpid(-1, &mut status as *mut i32, WAIT_ALL_THREADS) };
        if pid < 0 {
            let err = last_errno();
            if err == EINTR {
                continue;
            }
            if err == ECHILD {
                break;
            }
            continue;
        }
        drain_depth_updates(depth_read_fd, &mut depth_by_tid);
        drain_fgraph_window_updates(fgraph_window_read_fd, &mut fgraph_window_by_tid);

        if wifexited(status) || wifsignaled(status) {
            if active_fgraph_capture
                .as_ref()
                .map(|capture| capture.tid == pid)
                .unwrap_or(false)
            {
                let _ = finish_active_fgraph_capture(
                    &mut fgraph_controller,
                    &mut active_fgraph_capture,
                    global().path.as_str(),
                );
            }
            states.remove(&pid);
            depth_by_tid.remove(&pid);
            fgraph_window_by_tid.remove(&pid);
            waiting_fgraph_tids.retain(|queued| *queued != pid);
            writer.close_tid(pid);
            maybe_resume_waiting_fgraph_tid(
                &mut waiting_fgraph_tids,
                &mut states,
                &fd_paths,
                &fgraph_window_by_tid,
                &mut fgraph_controller,
                &mut active_fgraph_capture,
            );
            continue;
        }

        if !wifstopped(status) {
            continue;
        }

        let sig = wstopsig(status);
        if sig == SYSCALL_STOP_SIG {
            let mut hold_at_syscall_entry = false;
            let mut finished_fgraph_capture = false;
            if let Ok(regs) = ptrace_getregs(pid) {
                {
                    let state = states.entry(pid).or_default();
                    if !state.active {
                        state.active = true;
                        state.internal = is_internal_syscall(pid, &regs, &cudatrace_ranges);
                        state.nr = regs.orig_rax as i64;
                        state.args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
                        state.path_hint = capture_path_hint(pid, state.nr, &state.args);
                        state.started_ts = if global().left_meta.include_timestamp() {
                            now_timestamp_for_config()
                        } else {
                            0
                        };
                        state.started_ts_us = now_timestamp_us();
                        state.started_at = Instant::now();
                        state.fgraph_waiting = false;
                        state.fgraph_capturing = false;

                        if should_capture_fgraph(
                            pid,
                            state,
                            &fgraph_window_by_tid,
                            &fgraph_controller,
                        ) {
                            if active_fgraph_capture.is_none() {
                                state.fgraph_capturing = begin_fgraph_capture_for_state(
                                    pid,
                                    state,
                                    &fd_paths,
                                    &fgraph_window_by_tid,
                                    &mut fgraph_controller,
                                    &mut active_fgraph_capture,
                                );
                            } else {
                                state.fgraph_waiting = true;
                                if !waiting_fgraph_tids.contains(&pid) {
                                    waiting_fgraph_tids.push_back(pid);
                                }
                                hold_at_syscall_entry = true;
                            }
                        }
                    } else {
                        let ret_raw = regs.rax as i64;
                        let ret_norm = normalize_ret(ret_raw);

                        if state.fgraph_capturing {
                            finished_fgraph_capture = true;
                            state.fgraph_capturing = false;
                        }

                        if !state.internal {
                            let elapsed = state.started_at.elapsed();
                            let depth = depth_by_tid.get(&pid).copied().unwrap_or(0);
                            let line = format_syscall_line(
                                pid,
                                state,
                                ret_raw,
                                elapsed,
                                &fd_paths,
                                &hidden_fds,
                                depth,
                            );
                            if !line.is_empty() {
                                writer.write_line(pid, &line);
                            }
                        }
                        update_hidden_fds(pid, state, ret_norm, &mut hidden_fds);
                        update_fd_paths(&mut fd_paths, state, ret_norm);
                        state.active = false;
                        state.internal = false;
                        state.path_hint = None;
                        state.started_ts_us = 0;
                        state.fgraph_waiting = false;
                    }
                }
            }
            if hold_at_syscall_entry {
                continue;
            }
            if finished_fgraph_capture {
                let _ = finish_active_fgraph_capture(
                    &mut fgraph_controller,
                    &mut active_fgraph_capture,
                    global().path.as_str(),
                );
                maybe_resume_waiting_fgraph_tid(
                    &mut waiting_fgraph_tids,
                    &mut states,
                    &fd_paths,
                    &fgraph_window_by_tid,
                    &mut fgraph_controller,
                    &mut active_fgraph_capture,
                );
            }
            let _ = ptrace_syscall(pid, 0);
            continue;
        }

        let event = ptrace_event(status);
        if sig == SIGTRAP
            && (event == PTRACE_EVENT_CLONE
                || event == PTRACE_EVENT_FORK
                || event == PTRACE_EVENT_VFORK)
        {
            if let Ok(new_tid) = ptrace_geteventmsg(pid) {
                let new_tid = new_tid as pid_t;
                let _ = set_ptrace_options(new_tid);
                let _ = ptrace_syscall(new_tid, 0);
            }
            let _ = ptrace_syscall(pid, 0);
            continue;
        }

        if sig == SIGTRAP && event == PTRACE_EVENT_EXEC {
            cudatrace_ranges = load_cudatrace_ranges(pid);
            if debug_enabled() {
                debug_log(&format!(
                    "reloaded {} cudatrace map range(s) after exec pid={pid}",
                    cudatrace_ranges.len()
                ));
            }
            let _ = ptrace_syscall(pid, 0);
            continue;
        }

        let _ = ptrace_syscall(pid, sig);
    }

    if active_fgraph_capture.is_some() {
        let _ = finish_active_fgraph_capture(
            &mut fgraph_controller,
            &mut active_fgraph_capture,
            global().path.as_str(),
        );
    }
    if let Some(controller) = fgraph_controller.as_ref() {
        let _ = controller.reset_state();
    }
    let _ = call_real_close(depth_read_fd);
    let _ = call_real_close(fgraph_window_read_fd);
}

fn signal_ready(fd: i32, ok: bool) {
    let byte = [if ok { b'1' } else { b'0' }];
    // SAFETY: best-effort 1-byte readiness handshake.
    let _ = call_real_write(fd, byte.as_ptr().cast::<crate::ffi::c_void>(), 1);
}

fn ptrace_attach(pid: pid_t) -> Result<(), ()> {
    ptrace_call(
        PTRACE_ATTACH,
        pid,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )
    .map(|_| ())
}

fn ptrace_syscall(pid: pid_t, signal: i32) -> Result<(), ()> {
    ptrace_call(
        PTRACE_SYSCALL,
        pid,
        std::ptr::null_mut(),
        signal as usize as *mut crate::ffi::c_void,
    )
    .map(|_| ())
}

fn set_ptrace_options(pid: pid_t) -> Result<(), ()> {
    let opts = PTRACE_O_TRACESYSGOOD
        | PTRACE_O_TRACECLONE
        | PTRACE_O_TRACEFORK
        | PTRACE_O_TRACEVFORK
        | PTRACE_O_TRACEEXEC
        | PTRACE_O_TRACEEXIT;
    ptrace_call(
        PTRACE_SETOPTIONS,
        pid,
        std::ptr::null_mut(),
        opts as usize as *mut crate::ffi::c_void,
    )
    .map(|_| ())
}

fn ptrace_getregs(pid: pid_t) -> Result<UserRegsStruct, ()> {
    let mut regs = UserRegsStruct::default();
    ptrace_call(
        PTRACE_GETREGS,
        pid,
        std::ptr::null_mut(),
        (&mut regs as *mut UserRegsStruct).cast::<crate::ffi::c_void>(),
    )?;
    Ok(regs)
}

fn ptrace_geteventmsg(pid: pid_t) -> Result<u64, ()> {
    let mut value = 0_u64;
    ptrace_call(
        PTRACE_GETEVENTMSG,
        pid,
        std::ptr::null_mut(),
        (&mut value as *mut u64).cast::<crate::ffi::c_void>(),
    )?;
    Ok(value)
}

fn ptrace_call(
    request: i32,
    pid: pid_t,
    addr: *mut crate::ffi::c_void,
    data: *mut crate::ffi::c_void,
) -> Result<i64, ()> {
    // SAFETY: request/pid/addr/data follow ptrace ABI.
    let ret = unsafe { libc_ptrace(request, pid, addr, data) };
    if ret == -1 { Err(()) } else { Ok(ret) }
}

fn wait_for_stop(pid: pid_t) -> Result<(), ()> {
    loop {
        let mut status = 0_i32;
        // SAFETY: waiting for specific attached pid stop.
        let waited = unsafe { waitpid(pid, &mut status as *mut i32, 0) };
        if waited < 0 {
            let err = last_errno();
            if err == EINTR {
                continue;
            }
            return Err(());
        }
        if wifstopped(status) {
            return Ok(());
        }
        if wifexited(status) || wifsignaled(status) {
            return Err(());
        }
    }
}

fn set_nonblocking(fd: i32) -> Result<(), ()> {
    if fd < 0 {
        return Err(());
    }
    // SAFETY: fcntl called with valid command constants.
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if flags < 0 {
        return Err(());
    }
    // SAFETY: fcntl called with valid command constants.
    let ret = unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) };
    if ret < 0 { Err(()) } else { Ok(()) }
}

fn write_all(fd: i32, mut data: &[u8]) -> Result<(), ()> {
    while !data.is_empty() {
        // SAFETY: data points to valid initialized bytes.
        let written = call_real_write(fd, data.as_ptr().cast::<crate::ffi::c_void>(), data.len());
        if written < 0 {
            if last_errno() == EINTR {
                continue;
            }
            return Err(());
        }
        let written = written as usize;
        data = &data[written..];
    }
    Ok(())
}

fn depth_update_as_bytes(msg: &DepthUpdate) -> &[u8] {
    // SAFETY: DepthUpdate is POD and we only expose its in-memory bytes for IPC.
    unsafe {
        std::slice::from_raw_parts(
            (msg as *const DepthUpdate).cast::<u8>(),
            std::mem::size_of::<DepthUpdate>(),
        )
    }
}

fn fgraph_window_update_as_bytes(msg: &FgraphWindowUpdate) -> &[u8] {
    // SAFETY: FgraphWindowUpdate is POD and we only expose its in-memory bytes for IPC.
    unsafe {
        std::slice::from_raw_parts(
            (msg as *const FgraphWindowUpdate).cast::<u8>(),
            std::mem::size_of::<FgraphWindowUpdate>(),
        )
    }
}

fn drain_depth_updates(fd: i32, depth_by_tid: &mut HashMap<pid_t, usize>) {
    if fd < 0 {
        return;
    }
    let mut msg = DepthUpdate::default();
    let msg_size = std::mem::size_of::<DepthUpdate>();
    loop {
        let n = call_real_read(
            fd,
            (&mut msg as *mut DepthUpdate).cast::<crate::ffi::c_void>(),
            msg_size,
        );
        if n == msg_size as isize {
            depth_by_tid.insert(msg.tid, msg.depth as usize);
            continue;
        }
        if n < 0 {
            let err = last_errno();
            if err == EINTR {
                continue;
            }
            if err == EAGAIN || err == EWOULDBLOCK {
                break;
            }
        }
        break;
    }
}

fn drain_fgraph_window_updates(fd: i32, window_by_tid: &mut HashMap<pid_t, FgraphWindowState>) {
    if fd < 0 {
        return;
    }
    let mut msg = FgraphWindowUpdate::default();
    let msg_size = std::mem::size_of::<FgraphWindowUpdate>();
    loop {
        let n = call_real_read(
            fd,
            (&mut msg as *mut FgraphWindowUpdate).cast::<crate::ffi::c_void>(),
            msg_size,
        );
        if n == msg_size as isize {
            apply_fgraph_window_update(&msg, window_by_tid);
            continue;
        }
        if n < 0 {
            let err = last_errno();
            if err == EINTR {
                continue;
            }
            if err == EAGAIN || err == EWOULDBLOCK {
                break;
            }
        }
        break;
    }
}

fn apply_fgraph_window_update(
    msg: &FgraphWindowUpdate,
    window_by_tid: &mut HashMap<pid_t, FgraphWindowState>,
) {
    let depth = msg.depth as usize;
    if msg.event == FGRAPH_WINDOW_EVENT_ENTER {
        if depth == 0 {
            window_by_tid.remove(&msg.tid);
            return;
        }
        let state = window_by_tid.entry(msg.tid).or_default();
        state.depth = depth;
        state.labels.truncate(depth.saturating_sub(1));
        state.labels.push(FgraphScopeLabel {
            func: msg.func_name(),
            seq: msg.seq,
        });
        return;
    }

    if depth == 0 {
        window_by_tid.remove(&msg.tid);
        return;
    }
    let state = window_by_tid.entry(msg.tid).or_default();
    state.depth = depth;
    state.labels.truncate(depth);
}

fn current_fgraph_scope_label(
    tid: pid_t,
    window_by_tid: &HashMap<pid_t, FgraphWindowState>,
) -> Option<String> {
    window_by_tid
        .get(&tid)
        .and_then(|state| state.labels.last())
        .map(|label| format!("{}{}", label.func, label.seq))
}

fn now_timestamp_us() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
}

fn should_capture_fgraph(
    pid: pid_t,
    state: &SyscallState,
    window_by_tid: &HashMap<pid_t, FgraphWindowState>,
    controller: &Option<crate::hook::fgraph::TraceFsController>,
) -> bool {
    controller.is_some()
        && !state.internal
        && window_by_tid
            .get(&pid)
            .map(|state| state.depth)
            .unwrap_or(0)
            > 0
}

fn begin_fgraph_capture_for_state(
    pid: pid_t,
    state: &SyscallState,
    fd_paths: &HashMap<i32, String>,
    window_by_tid: &HashMap<pid_t, FgraphWindowState>,
    controller: &mut Option<crate::hook::fgraph::TraceFsController>,
    active_capture: &mut Option<ActiveFgraphCapture>,
) -> bool {
    let Some(controller) = controller.as_ref() else {
        return false;
    };
    let graph_function = syscall_graph_function(state.nr);
    if let Err(err) = controller.begin_capture(pid, graph_function.as_deref()) {
        log_fgraph_error(&format!(
            "failed to begin function_graph capture for tid={pid}: {err}"
        ));
        return false;
    }
    let scope_label =
        current_fgraph_scope_label(pid, window_by_tid).unwrap_or_else(|| "unknown0".to_owned());

    *active_capture = Some(ActiveFgraphCapture {
        tid: pid,
        syscall_name: syscall_name(state.nr),
        graph_function,
        syscall_enter: format_fgraph_syscall_enter(pid, state, fd_paths),
        entry_ts_us: state.started_ts_us,
        scope_label,
    });
    true
}

fn finish_active_fgraph_capture(
    controller: &mut Option<crate::hook::fgraph::TraceFsController>,
    active_capture: &mut Option<ActiveFgraphCapture>,
    base_path: &str,
) -> Result<(), ()> {
    let Some(capture) = active_capture.take() else {
        return Ok(());
    };
    let Some(controller) = controller.as_ref() else {
        return Ok(());
    };

    let graph = match controller.end_capture_and_read() {
        Ok(graph) => graph,
        Err(err) => {
            log_fgraph_error(&format!(
                "failed to finish function_graph capture for tid={}: {err}",
                capture.tid
            ));
            let _ = controller.reset_state();
            return Err(());
        }
    };

    let path = fgraph_output_path(
        base_path,
        capture.tid,
        &capture.syscall_name,
        capture.entry_ts_us,
        &capture.scope_label,
    );
    let mut out = String::new();
    let _ = writeln!(
        &mut out,
        "tid={} syscall={} entry_ts_us={}",
        capture.tid, capture.syscall_name, capture.entry_ts_us
    );
    let _ = writeln!(&mut out, "scope={}", capture.scope_label);
    if let Some(graph_function) = capture.graph_function.as_deref() {
        let _ = writeln!(&mut out, "graph_function={graph_function}");
    }
    let _ = writeln!(&mut out, "syscall_enter={}", capture.syscall_enter);
    out.push_str(&sanitize_fgraph_trace_output(&graph));
    if std::fs::write(&path, out.as_bytes()).is_err() {
        log_fgraph_error(&format!("failed to write function_graph output: {path}"));
        return Err(());
    }
    Ok(())
}

fn sanitize_fgraph_trace_output(graph: &str) -> String {
    let mut out = String::with_capacity(graph.len());
    let mut depth = 0_usize;
    for line in graph.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("------------------------------------------") {
            continue;
        }
        if line.contains("=>") {
            continue;
        }
        let body = if let Some(idx) = line.find('|') {
            let mut body = &line[idx + 1..];
            if let Some(rest) = body.strip_prefix(' ') {
                body = rest;
            }
            body.trim()
        } else {
            trimmed.trim()
        };
        if body.is_empty() {
            continue;
        }

        if body.starts_with('}') {
            depth = depth.saturating_sub(1);
        }

        out.push_str(&"\t".repeat(depth));
        out.push_str(body);
        out.push('\n');

        if body.ends_with('{') {
            depth = depth.saturating_add(1);
        }
    }
    if out.is_empty() {
        graph.to_owned()
    } else {
        out
    }
}

fn format_fgraph_syscall_enter(
    pid: pid_t,
    state: &SyscallState,
    fd_paths: &HashMap<i32, String>,
) -> String {
    match state.nr {
        SYS_IOCTL => {
            let fd = state.args[0] as i32;
            let cmd = state.args[1];
            let arg = state.args[2];
            let fallback_path = if fd_paths.contains_key(&fd) {
                None
            } else {
                read_live_fd_path(pid, fd)
            };
            let suffix = format_fd_suffix(
                state
                    .path_hint
                    .as_deref()
                    .or(fd_paths.get(&fd).map(String::as_str))
                    .or(fallback_path.as_deref()),
            );
            format!("ioctl(fd={fd}{suffix}, cmd=0x{cmd:x}, arg=0x{arg:x})")
        }
        SYS_OPEN => {
            let path = state.path_hint.as_deref().unwrap_or("<unreadable>");
            let flags = format_open_flags(state.args[1]);
            let mode = state.args[2];
            format!("open(path=\"{path}\", flags={flags}, mode=0{mode:o})")
        }
        SYS_OPENAT => {
            let dirfd = format_dirfd(state.args[0] as i32);
            let path = state.path_hint.as_deref().unwrap_or("<unreadable>");
            let flags = format_open_flags(state.args[2]);
            let mode = state.args[3];
            format!("openat(dirfd={dirfd}, path=\"{path}\", flags={flags}, mode=0{mode:o})")
        }
        SYS_CLOSE => {
            let fd = state.args[0] as i32;
            let fallback_path = if fd_paths.contains_key(&fd) {
                None
            } else {
                read_live_fd_path(pid, fd)
            };
            let suffix = format_fd_suffix(
                state
                    .path_hint
                    .as_deref()
                    .or(fd_paths.get(&fd).map(String::as_str))
                    .or(fallback_path.as_deref()),
            );
            format!("close(fd={fd}{suffix})")
        }
        _ => {
            let name = syscall_name(state.nr);
            format!(
                "{name}(0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x})",
                state.args[0],
                state.args[1],
                state.args[2],
                state.args[3],
                state.args[4],
                state.args[5]
            )
        }
    }
}

fn maybe_resume_waiting_fgraph_tid(
    waiting_tids: &mut VecDeque<pid_t>,
    states: &mut HashMap<pid_t, SyscallState>,
    fd_paths: &HashMap<i32, String>,
    window_by_tid: &HashMap<pid_t, FgraphWindowState>,
    controller: &mut Option<crate::hook::fgraph::TraceFsController>,
    active_capture: &mut Option<ActiveFgraphCapture>,
) {
    if active_capture.is_some() {
        return;
    }

    while let Some(tid) = waiting_tids.pop_front() {
        let Some(state) = states.get_mut(&tid) else {
            continue;
        };
        if !state.active || !state.fgraph_waiting {
            continue;
        }
        state.fgraph_waiting = false;

        if should_capture_fgraph(tid, state, window_by_tid, controller) {
            state.fgraph_capturing = begin_fgraph_capture_for_state(
                tid,
                state,
                fd_paths,
                window_by_tid,
                controller,
                active_capture,
            );
        } else {
            state.fgraph_capturing = false;
        }

        let _ = ptrace_syscall(tid, 0);
        if active_capture.is_some() {
            break;
        }
    }
}

fn fgraph_output_path(
    base_path: &str,
    tid: pid_t,
    syscall: &str,
    entry_ts_us: u128,
    scope_label: &str,
) -> String {
    let scope = sanitize_scope_label_component(scope_label);
    format!(
        "{}.fgraph.tid-{}.ts-{}.{}.sys-{}.log",
        base_path,
        tid,
        entry_ts_us,
        scope,
        sanitize_file_component(syscall)
    )
}

fn syscall_graph_function(nr: i64) -> Option<String> {
    let name = syscall_name(nr);
    if name.starts_with("syscall_") {
        return None;
    }
    Some(format!("__x64_sys_{name}"))
}

fn sanitize_file_component(input: &str) -> String {
    input
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn sanitize_scope_label_component(input: &str) -> String {
    let cleaned = sanitize_file_component(input);
    if cleaned.is_empty() {
        "unknown0".to_owned()
    } else {
        cleaned
    }
}

fn load_cudatrace_ranges(pid: pid_t) -> Vec<(u64, u64)> {
    let path = format!("/proc/{pid}/maps");
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };

    let mut ranges = Vec::new();
    for line in text.lines() {
        if !line.contains("cudatrace") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(range_raw) = parts.next() else {
            continue;
        };
        let Some((start_raw, end_raw)) = range_raw.split_once('-') else {
            continue;
        };
        let Ok(start) = u64::from_str_radix(start_raw, 16) else {
            continue;
        };
        let Ok(end) = u64::from_str_radix(end_raw, 16) else {
            continue;
        };
        if end > start {
            ranges.push((start, end));
        }
    }
    ranges
}

fn is_internal_syscall(pid: pid_t, regs: &UserRegsStruct, ranges: &[(u64, u64)]) -> bool {
    if ranges.is_empty() {
        return false;
    }
    // Fast path: syscall entry RIP is inside libcudatrace mapping.
    if in_ranges(regs.rip, ranges) {
        return true;
    }

    // Some internal calls enter kernel through libc/vdso stubs, so RIP no longer points
    // to libcudatrace code. In that case, probe a few stack slots around RSP and treat
    // a return address into libcudatrace mappings as internal.
    const STACK_WORDS_TO_SCAN: usize = 16;
    let want = STACK_WORDS_TO_SCAN * std::mem::size_of::<u64>();
    let Some(bytes) = read_remote_bytes(pid, regs.rsp, want) else {
        return false;
    };
    for chunk in bytes.chunks_exact(std::mem::size_of::<u64>()) {
        let mut raw = [0_u8; std::mem::size_of::<u64>()];
        raw.copy_from_slice(chunk);
        if in_ranges(u64::from_ne_bytes(raw), ranges) {
            return true;
        }
    }
    false
}

fn in_ranges(addr: u64, ranges: &[(u64, u64)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| addr >= *start && addr < *end)
}

fn capture_path_hint(pid: pid_t, nr: i64, args: &[u64; 6]) -> Option<String> {
    match nr {
        SYS_OPEN | SYS_STAT | SYS_LSTAT | SYS_ACCESS => Some(read_remote_cstring(pid, args[0])),
        SYS_OPENAT | SYS_NEWFSTATAT | SYS_FACCESSAT => Some(read_remote_cstring(pid, args[1])),
        SYS_CLOSE => read_live_fd_path(pid, args[0] as i32),
        _ => None,
    }
}

fn read_remote_cstring(pid: pid_t, addr: u64) -> String {
    if addr == 0 {
        return "<null>".to_owned();
    }

    const CHUNK: usize = 256;
    const MAX_LEN: usize = 4096;

    let mut out = Vec::new();
    let mut cursor = addr;
    while out.len() < MAX_LEN {
        let remaining = MAX_LEN - out.len();
        let want = remaining.min(CHUNK);
        let Some(bytes) = read_remote_bytes(pid, cursor, want) else {
            break;
        };
        if bytes.is_empty() {
            break;
        }
        if let Some(zero_pos) = bytes.iter().position(|&b| b == 0) {
            out.extend_from_slice(&bytes[..zero_pos]);
            return String::from_utf8_lossy(&out).into_owned();
        }
        out.extend_from_slice(&bytes);
        if bytes.len() < want {
            break;
        }
        cursor = cursor.saturating_add(bytes.len() as u64);
    }

    if out.is_empty() {
        format!("<unreadable@0x{addr:x}>")
    } else {
        String::from_utf8_lossy(&out).into_owned()
    }
}

fn read_remote_bytes(pid: pid_t, remote_addr: u64, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    let mut out = vec![0_u8; len];
    let local_iov = crate::ffi::iovec {
        iov_base: out.as_mut_ptr().cast::<crate::ffi::c_void>(),
        iov_len: len,
    };
    let remote_iov = crate::ffi::iovec {
        iov_base: remote_addr as usize as *mut crate::ffi::c_void,
        iov_len: len,
    };
    // SAFETY: iovec pointers are valid for process_vm_readv ABI.
    let copied = unsafe { crate::ffi::process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) };
    if copied <= 0 {
        None
    } else {
        out.truncate(copied as usize);
        Some(out)
    }
}

fn bytes_to_ascii_preview(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(byte as char),
            _ => {
                let _ = write!(&mut out, "\\x{byte:02x}");
            }
        }
    }
    out
}

fn format_buffer_preview(pid: pid_t, buf_addr: u64, req_count: u64, ret_norm: i64) -> String {
    if ret_norm <= 0 {
        return String::new();
    }

    let observed = ret_norm as usize;
    let requested = usize::try_from(req_count).unwrap_or(usize::MAX);
    let expected = observed.min(requested);
    if expected == 0 {
        return String::new();
    }

    let preview_len = expected.min(global().max_blob);
    if preview_len == 0 {
        return ", data_truncated=true".to_owned();
    }

    let Some(bytes) = read_remote_bytes(pid, buf_addr, preview_len) else {
        return format!(", data=\"<unreadable@0x{buf_addr:x}>\"");
    };
    let ascii = bytes_to_ascii_preview(&bytes);
    let truncated = bytes.len() < expected || expected > preview_len;

    if truncated {
        format!(", data=\"{ascii}\", data_truncated=true")
    } else {
        format!(", data=\"{ascii}\"")
    }
}

fn format_dirfd(dirfd: i32) -> String {
    if dirfd == crate::ffi::AT_FDCWD {
        "AT_FDCWD".to_owned()
    } else {
        dirfd.to_string()
    }
}

fn format_open_flags(flags: u64) -> String {
    let mut parts: Vec<String> = Vec::new();
    match flags & O_ACCMODE_MASK {
        0 => parts.push("O_RDONLY".to_owned()),
        O_WRONLY_MASK => parts.push("O_WRONLY".to_owned()),
        O_RDWR_MASK => parts.push("O_RDWR".to_owned()),
        value => parts.push(format!("O_ACCMODE(0x{value:x})")),
    }

    let mut remaining = flags & !O_ACCMODE_MASK;
    if (remaining & O_TMPFILE_MASK) == O_TMPFILE_MASK {
        parts.push("O_TMPFILE".to_owned());
        remaining &= !O_TMPFILE_MASK;
    }

    let specs = [
        (O_CREAT_MASK, "O_CREAT"),
        (O_EXCL_MASK, "O_EXCL"),
        (O_NOCTTY_MASK, "O_NOCTTY"),
        (O_TRUNC_MASK, "O_TRUNC"),
        (O_APPEND_MASK, "O_APPEND"),
        (O_NONBLOCK as u64, "O_NONBLOCK"),
        (O_DIRECT_MASK, "O_DIRECT"),
        (O_SYNC_MASK, "O_SYNC"),
        (O_DSYNC_MASK, "O_DSYNC"),
        (O_LARGEFILE_MASK, "O_LARGEFILE"),
        (O_DIRECTORY_MASK, "O_DIRECTORY"),
        (O_NOFOLLOW_MASK, "O_NOFOLLOW"),
        (O_NOATIME_MASK, "O_NOATIME"),
        (O_CLOEXEC_MASK, "O_CLOEXEC"),
        (O_PATH_MASK, "O_PATH"),
    ];
    for (mask, name) in specs {
        if (remaining & mask) == mask {
            parts.push(name.to_owned());
            remaining &= !mask;
        }
    }
    if remaining != 0 {
        parts.push(format!("0x{remaining:x}"));
    }

    format!("{}(0x{flags:x})", parts.join("|"))
}

fn format_dup3_flags(flags: u64) -> String {
    if flags == 0 {
        return "0".to_owned();
    }
    let mut parts: Vec<String> = Vec::new();
    let mut remaining = flags;
    if (remaining & O_CLOEXEC_MASK) == O_CLOEXEC_MASK {
        parts.push("O_CLOEXEC".to_owned());
        remaining &= !O_CLOEXEC_MASK;
    }
    if remaining != 0 {
        parts.push(format!("0x{remaining:x}"));
    }
    format!("{}(0x{flags:x})", parts.join("|"))
}

fn format_mmap_prot(prot: u64) -> String {
    if prot == PROT_NONE_MASK {
        return "PROT_NONE(0x0)".to_owned();
    }
    let mut parts: Vec<String> = Vec::new();
    let mut remaining = prot;
    let specs = [
        (PROT_READ_MASK, "PROT_READ"),
        (PROT_WRITE_MASK, "PROT_WRITE"),
        (PROT_EXEC_MASK, "PROT_EXEC"),
        (PROT_SEM_MASK, "PROT_SEM"),
        (PROT_GROWSDOWN_MASK, "PROT_GROWSDOWN"),
        (PROT_GROWSUP_MASK, "PROT_GROWSUP"),
    ];
    for (mask, name) in specs {
        if (remaining & mask) == mask {
            parts.push(name.to_owned());
            remaining &= !mask;
        }
    }
    if remaining != 0 {
        parts.push(format!("0x{remaining:x}"));
    }
    format!("{}(0x{prot:x})", parts.join("|"))
}

fn format_mmap_flags(flags: u64) -> String {
    if flags == 0 {
        return "0".to_owned();
    }
    let mut parts: Vec<String> = Vec::new();
    let map_type = flags & MAP_TYPE_MASK;
    let mut remaining = flags & !MAP_TYPE_MASK;

    match map_type {
        MAP_SHARED_MASK => parts.push("MAP_SHARED".to_owned()),
        MAP_PRIVATE_MASK => parts.push("MAP_PRIVATE".to_owned()),
        MAP_SHARED_VALIDATE_MASK => parts.push("MAP_SHARED_VALIDATE".to_owned()),
        0 => {}
        value => parts.push(format!("MAP_TYPE(0x{value:x})")),
    }

    let specs = [
        (MAP_FIXED_MASK, "MAP_FIXED"),
        (MAP_ANONYMOUS_MASK, "MAP_ANONYMOUS"),
        (MAP_32BIT_MASK, "MAP_32BIT"),
        (MAP_GROWSDOWN_MASK, "MAP_GROWSDOWN"),
        (MAP_DENYWRITE_MASK, "MAP_DENYWRITE"),
        (MAP_EXECUTABLE_MASK, "MAP_EXECUTABLE"),
        (MAP_LOCKED_MASK, "MAP_LOCKED"),
        (MAP_NORESERVE_MASK, "MAP_NORESERVE"),
        (MAP_POPULATE_MASK, "MAP_POPULATE"),
        (MAP_NONBLOCK_MASK, "MAP_NONBLOCK"),
        (MAP_STACK_MASK, "MAP_STACK"),
        (MAP_HUGETLB_MASK, "MAP_HUGETLB"),
        (MAP_SYNC_MASK, "MAP_SYNC"),
        (MAP_FIXED_NOREPLACE_MASK, "MAP_FIXED_NOREPLACE"),
    ];
    for (mask, name) in specs {
        if (remaining & mask) == mask {
            parts.push(name.to_owned());
            remaining &= !mask;
        }
    }
    if remaining != 0 {
        parts.push(format!("0x{remaining:x}"));
    }

    if parts.is_empty() {
        format!("0x{flags:x}")
    } else {
        format!("{}(0x{flags:x})", parts.join("|"))
    }
}

fn format_access_mode(mode: u64) -> String {
    if mode == F_OK_MASK {
        return "F_OK(0x0)".to_owned();
    }
    let mut parts: Vec<String> = Vec::new();
    let mut remaining = mode;
    if (remaining & R_OK_MASK) == R_OK_MASK {
        parts.push("R_OK".to_owned());
        remaining &= !R_OK_MASK;
    }
    if (remaining & W_OK_MASK) == W_OK_MASK {
        parts.push("W_OK".to_owned());
        remaining &= !W_OK_MASK;
    }
    if (remaining & X_OK_MASK) == X_OK_MASK {
        parts.push("X_OK".to_owned());
        remaining &= !X_OK_MASK;
    }
    if remaining != 0 {
        parts.push(format!("0x{remaining:x}"));
    }
    format!("{}(0x{mode:x})", parts.join("|"))
}

fn format_newfstatat_flags(flags: u64) -> String {
    format_named_at_flags(
        flags,
        &[
            (AT_SYMLINK_NOFOLLOW_MASK, "AT_SYMLINK_NOFOLLOW"),
            (AT_NO_AUTOMOUNT_MASK, "AT_NO_AUTOMOUNT"),
            (AT_EMPTY_PATH_MASK, "AT_EMPTY_PATH"),
        ],
    )
}

fn format_faccessat_flags(flags: u64) -> String {
    format_named_at_flags(
        flags,
        &[
            (AT_EACCESS_MASK, "AT_EACCESS"),
            (AT_SYMLINK_NOFOLLOW_MASK, "AT_SYMLINK_NOFOLLOW"),
            (AT_EMPTY_PATH_MASK, "AT_EMPTY_PATH"),
        ],
    )
}

fn format_named_at_flags(flags: u64, specs: &[(u64, &str)]) -> String {
    if flags == 0 {
        return "0".to_owned();
    }
    let mut parts: Vec<String> = Vec::new();
    let mut remaining = flags;
    for (mask, name) in specs {
        if (remaining & *mask) == *mask {
            parts.push((*name).to_owned());
            remaining &= !*mask;
        }
    }
    if remaining != 0 {
        parts.push(format!("0x{remaining:x}"));
    }
    format!("{}(0x{flags:x})", parts.join("|"))
}

fn format_lseek_whence(whence: u64) -> String {
    match whence {
        SEEK_SET => "SEEK_SET(0x0)".to_owned(),
        SEEK_CUR => "SEEK_CUR(0x1)".to_owned(),
        SEEK_END => "SEEK_END(0x2)".to_owned(),
        SEEK_DATA => "SEEK_DATA(0x3)".to_owned(),
        SEEK_HOLE => "SEEK_HOLE(0x4)".to_owned(),
        value => format!("0x{value:x}"),
    }
}

fn read_live_fd_path(pid: pid_t, fd: i32) -> Option<String> {
    if fd < 0 {
        return None;
    }
    // This runs in the tracer child process only, so these /proc reads are never
    // emitted as traced syscalls from the target process.
    let link = format!("/proc/{pid}/fd/{fd}");
    let path = std::fs::read_link(link).ok()?;
    Some(path.to_string_lossy().into_owned())
}

fn format_open_return(ret_norm: i64, path: Option<&str>) -> String {
    if ret_norm < 0 {
        return ret_norm.to_string();
    }
    let Some(path) = path else {
        return ret_norm.to_string();
    };
    if path.starts_with('<') {
        return ret_norm.to_string();
    }
    format!("{ret_norm}({path})")
}

fn format_syscall_line(
    pid: pid_t,
    state: &SyscallState,
    ret_raw: i64,
    elapsed: std::time::Duration,
    fd_paths: &HashMap<i32, String>,
    hidden_fds: &HashSet<i32>,
    depth: usize,
) -> String {
    let (elapsed_value, elapsed_unit) = duration_for_config(elapsed);
    let ret_norm = normalize_ret(ret_raw);

    if is_hidden_fd_syscall(state, hidden_fds) {
        return String::new();
    }
    if (state.nr == SYS_OPEN || state.nr == SYS_OPENAT)
        && ret_norm >= 0
        && is_cudatrace_output_open(pid, state)
    {
        return String::new();
    }

    let line = match state.nr {
        SYS_OPEN => {
            let path = state.path_hint.as_deref().unwrap_or("<unreadable>");
            let flags = state.args[1];
            let flags_text = format_open_flags(flags);
            let mode = state.args[2];
            let ret_text = format_open_return(ret_norm, state.path_hint.as_deref());
            if (flags & O_CREAT_MASK) != 0 {
                format!(
                    "open(path=\"{path}\", flags={flags_text}, mode=0{mode:o}) = {ret_text}  /* {elapsed_value} {elapsed_unit} */"
                )
            } else {
                format!(
                    "open(path=\"{path}\", flags={flags_text}) = {ret_text}  /* {elapsed_value} {elapsed_unit} */"
                )
            }
        }
        SYS_OPENAT => {
            let dirfd = state.args[0] as i32;
            let dirfd_text = format_dirfd(dirfd);
            let path = state.path_hint.as_deref().unwrap_or("<unreadable>");
            let flags = state.args[2];
            let flags_text = format_open_flags(flags);
            let mode = state.args[3];
            let ret_text = format_open_return(ret_norm, state.path_hint.as_deref());
            if (flags & O_CREAT_MASK) != 0 {
                format!(
                    "openat(dirfd={dirfd_text}, path=\"{path}\", flags={flags_text}, mode=0{mode:o}) = {ret_text}  /* {elapsed_value} {elapsed_unit} */"
                )
            } else {
                format!(
                    "openat(dirfd={dirfd_text}, path=\"{path}\", flags={flags_text}) = {ret_text}  /* {elapsed_value} {elapsed_unit} */"
                )
            }
        }
        SYS_CLOSE => {
            let fd = state.args[0] as i32;
            let fallback_path = if fd_paths.contains_key(&fd) {
                None
            } else {
                read_live_fd_path(pid, fd)
            };
            let suffix = format_fd_suffix(
                state
                    .path_hint
                    .as_deref()
                    .or(fd_paths.get(&fd).map(String::as_str))
                    .or(fallback_path.as_deref()),
            );
            format!(
                "close(fd={fd}{suffix}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_DUP => {
            let oldfd = state.args[0] as i32;
            let suffix = format_fd_suffix(fd_paths.get(&oldfd).map(String::as_str));
            format!(
                "dup(oldfd={oldfd}{suffix}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_DUP2 => {
            let oldfd = state.args[0] as i32;
            let newfd = state.args[1] as i32;
            let suffix = format_fd_suffix(fd_paths.get(&oldfd).map(String::as_str));
            format!(
                "dup2(oldfd={oldfd}{suffix} , newfd={newfd}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_DUP3 => {
            let oldfd = state.args[0] as i32;
            let newfd = state.args[1] as i32;
            let flags = state.args[2];
            let flags_text = format_dup3_flags(flags);
            let suffix = format_fd_suffix(fd_paths.get(&oldfd).map(String::as_str));
            format!(
                "dup3(oldfd={oldfd}{suffix} , newfd={newfd}, flags={flags_text}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_MMAP => {
            let fd = state.args[4] as i32;
            let suffix = if fd >= 0 {
                format_fd_suffix(fd_paths.get(&fd).map(String::as_str))
            } else {
                String::new()
            };
            let addr = state.args[0];
            let length = state.args[1];
            let prot = state.args[2];
            let prot_text = format_mmap_prot(prot);
            let flags = state.args[3];
            let flags_text = format_mmap_flags(flags);
            let offset = state.args[5] as i64;
            let ret_text = if is_kernel_error(ret_raw) {
                "MAP_FAILED".to_owned()
            } else {
                format!("0x{:x}", ret_raw as u64)
            };
            if fd >= 0 {
                format!(
                    "mmap(addr=0x{addr:x}, length={length}, prot={prot_text}, flags={flags_text}, fd={fd}{suffix} , offset={offset}) = {ret_text}  /* {elapsed_value} {elapsed_unit} */"
                )
            } else {
                format!(
                    "mmap(addr=0x{addr:x}, length={length}, prot={prot_text}, flags={flags_text}, fd={fd}, offset={offset}) = {ret_text}  /* {elapsed_value} {elapsed_unit} */"
                )
            }
        }
        SYS_MUNMAP => {
            let addr = state.args[0];
            let length = state.args[1];
            format!(
                "munmap(addr=0x{addr:x}, length={length}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_READ => {
            let fd = state.args[0] as i32;
            let buf = state.args[1];
            let count = state.args[2];
            let preview = format_buffer_preview(pid, buf, count, ret_norm);
            let suffix = format_fd_suffix(fd_paths.get(&fd).map(String::as_str));
            if suffix.is_empty() {
                format!(
                    "read(fd={fd}, buf=0x{buf:x}, count={count}{preview}) = {}  /* {elapsed_value} {elapsed_unit} */",
                    ret_norm
                )
            } else {
                format!(
                    "read(fd={fd}{suffix} , buf=0x{buf:x}, count={count}{preview}) = {}  /* {elapsed_value} {elapsed_unit} */",
                    ret_norm
                )
            }
        }
        SYS_WRITE => {
            let fd = state.args[0] as i32;
            let buf = state.args[1];
            let count = state.args[2];
            let preview = format_buffer_preview(pid, buf, count, ret_norm);
            let suffix = format_fd_suffix(fd_paths.get(&fd).map(String::as_str));
            if suffix.is_empty() {
                format!(
                    "write(fd={fd}, buf=0x{buf:x}, count={count}{preview}) = {}  /* {elapsed_value} {elapsed_unit} */",
                    ret_norm
                )
            } else {
                format!(
                    "write(fd={fd}{suffix} , buf=0x{buf:x}, count={count}{preview}) = {}  /* {elapsed_value} {elapsed_unit} */",
                    ret_norm
                )
            }
        }
        SYS_POLL => {
            let fds = state.args[0];
            let nfds = state.args[1];
            let timeout = state.args[2] as i32;
            format!(
                "poll(fds=0x{fds:x}, nfds={nfds}, timeout={timeout}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_PPOLL => {
            let fds = state.args[0];
            let nfds = state.args[1];
            let timeout = state.args[2];
            let sigmask = state.args[3];
            format!(
                "ppoll(fds=0x{fds:x}, nfds={nfds}, timeout=0x{timeout:x}, sigmask=0x{sigmask:x}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_SELECT => {
            let nfds = state.args[0] as i32;
            let readfds = state.args[1];
            let writefds = state.args[2];
            let exceptfds = state.args[3];
            let timeout = state.args[4];
            format!(
                "select(nfds={nfds}, readfds=0x{readfds:x}, writefds=0x{writefds:x}, exceptfds=0x{exceptfds:x}, timeout=0x{timeout:x}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_PSELECT6 => {
            let nfds = state.args[0] as i32;
            let readfds = state.args[1];
            let writefds = state.args[2];
            let exceptfds = state.args[3];
            let timeout = state.args[4];
            let sigmask = state.args[5];
            format!(
                "pselect(nfds={nfds}, readfds=0x{readfds:x}, writefds=0x{writefds:x}, exceptfds=0x{exceptfds:x}, timeout=0x{timeout:x}, sigmask=0x{sigmask:x}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_STAT => {
            let path = state.path_hint.as_deref().unwrap_or("<unreadable>");
            let statbuf = state.args[1];
            format!(
                "stat(path=\"{path}\", statbuf=0x{statbuf:x}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_LSTAT => {
            let path = state.path_hint.as_deref().unwrap_or("<unreadable>");
            let statbuf = state.args[1];
            format!(
                "lstat(path=\"{path}\", statbuf=0x{statbuf:x}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_FSTAT => {
            let fd = state.args[0] as i32;
            let statbuf = state.args[1];
            let suffix = format_fd_suffix(fd_paths.get(&fd).map(String::as_str));
            if suffix.is_empty() {
                format!(
                    "fstat(fd={fd}, statbuf=0x{statbuf:x}) = {}  /* {elapsed_value} {elapsed_unit} */",
                    ret_norm
                )
            } else {
                format!(
                    "fstat(fd={fd}{suffix} , statbuf=0x{statbuf:x}) = {}  /* {elapsed_value} {elapsed_unit} */",
                    ret_norm
                )
            }
        }
        SYS_NEWFSTATAT => {
            let dirfd = state.args[0] as i32;
            let dirfd_text = format_dirfd(dirfd);
            let path = state.path_hint.as_deref().unwrap_or("<unreadable>");
            let statbuf = state.args[2];
            let flags = state.args[3];
            let flags_text = format_newfstatat_flags(flags);
            format!(
                "newfstatat(dirfd={dirfd_text}, path=\"{path}\", statbuf=0x{statbuf:x}, flags={flags_text}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_ACCESS => {
            let path = state.path_hint.as_deref().unwrap_or("<unreadable>");
            let mode = state.args[1];
            let mode_text = format_access_mode(mode);
            format!(
                "access(path=\"{path}\", mode={mode_text}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_FACCESSAT => {
            let dirfd = state.args[0] as i32;
            let dirfd_text = format_dirfd(dirfd);
            let path = state.path_hint.as_deref().unwrap_or("<unreadable>");
            let mode = state.args[2];
            let mode_text = format_access_mode(mode);
            let flags = state.args[3];
            let flags_text = format_faccessat_flags(flags);
            format!(
                "faccessat(dirfd={dirfd_text}, path=\"{path}\", mode={mode_text}, flags={flags_text}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_LSEEK => {
            let fd = state.args[0] as i32;
            let offset = state.args[1] as i64;
            let whence = state.args[2];
            let whence_text = format_lseek_whence(whence);
            let suffix = format_fd_suffix(fd_paths.get(&fd).map(String::as_str));
            if suffix.is_empty() {
                format!(
                    "lseek(fd={fd}, offset={offset}, whence={whence_text}) = {}  /* {elapsed_value} {elapsed_unit} */",
                    ret_norm
                )
            } else {
                format!(
                    "lseek(fd={fd}{suffix} , offset={offset}, whence={whence_text}) = {}  /* {elapsed_value} {elapsed_unit} */",
                    ret_norm
                )
            }
        }
        SYS_PREAD64 => {
            let fd = state.args[0] as i32;
            let buf = state.args[1];
            let count = state.args[2];
            let offset = state.args[3] as i64;
            let preview = format_buffer_preview(pid, buf, count, ret_norm);
            let suffix = format_fd_suffix(fd_paths.get(&fd).map(String::as_str));
            if suffix.is_empty() {
                format!(
                    "pread(fd={fd}, buf=0x{buf:x}, count={count}, offset={offset}{preview}) = {}  /* {elapsed_value} {elapsed_unit} */",
                    ret_norm
                )
            } else {
                format!(
                    "pread(fd={fd}{suffix} , buf=0x{buf:x}, count={count}, offset={offset}{preview}) = {}  /* {elapsed_value} {elapsed_unit} */",
                    ret_norm
                )
            }
        }
        SYS_PWRITE64 => {
            let fd = state.args[0] as i32;
            let buf = state.args[1];
            let count = state.args[2];
            let offset = state.args[3] as i64;
            let preview = format_buffer_preview(pid, buf, count, ret_norm);
            let suffix = format_fd_suffix(fd_paths.get(&fd).map(String::as_str));
            if suffix.is_empty() {
                format!(
                    "pwrite(fd={fd}, buf=0x{buf:x}, count={count}, offset={offset}{preview}) = {}  /* {elapsed_value} {elapsed_unit} */",
                    ret_norm
                )
            } else {
                format!(
                    "pwrite(fd={fd}{suffix} , buf=0x{buf:x}, count={count}, offset={offset}{preview}) = {}  /* {elapsed_value} {elapsed_unit} */",
                    ret_norm
                )
            }
        }
        SYS_PRCTL => {
            let option = state.args[0] as i32;
            let arg2 = state.args[1];
            let arg3 = state.args[2];
            let arg4 = state.args[3];
            let arg5 = state.args[4];
            format!(
                "prctl(option={option}, arg2=0x{arg2:x}, arg3=0x{arg3:x}, arg4=0x{arg4:x}, arg5=0x{arg5:x}) = {}  /* {elapsed_value} {elapsed_unit} */",
                ret_norm
            )
        }
        SYS_IOCTL => format_ioctl_line(pid, state, ret_norm, elapsed_value, elapsed_unit, fd_paths),
        SYS_FUTEX => {
            format!(
                "futex(uaddr=0x{:x}, futex_op=0x{:x}, val={}, timeout_or_val2=0x{:x}, uaddr2=0x{:x}, val3={}) = {}  /* {elapsed_value} {elapsed_unit} */",
                state.args[0],
                state.args[1],
                state.args[2] as i32,
                state.args[3],
                state.args[4],
                state.args[5] as i32,
                ret_norm
            )
        }
        _ => {
            let name = syscall_name(state.nr);
            format!(
                "{name}(0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}) = {}  /* {elapsed_value} {elapsed_unit} */",
                state.args[0],
                state.args[1],
                state.args[2],
                state.args[3],
                state.args[4],
                state.args[5],
                ret_norm
            )
        }
    };

    let indented = indent_ptrace_line(line, depth);
    prepend_left_meta(&indented, pid, state.started_ts)
}

fn format_ioctl_line(
    pid: pid_t,
    state: &SyscallState,
    ret_norm: i64,
    elapsed_value: u128,
    elapsed_unit: &str,
    fd_paths: &HashMap<i32, String>,
) -> String {
    let fd = state.args[0] as i32;
    let cmd = state.args[1] as crate::ffi::c_ulong;
    let arg = state.args[2] as usize as *mut crate::ffi::c_void;
    let path = fd_paths.get(&fd);
    let gpu_related = path
        .as_ref()
        .map(|p| crate::fd_map::is_gpu_path(p))
        .unwrap_or(false);

    let cfg = global();
    let cmd_summary = if gpu_related {
        set_decode_target_pid(Some(pid));
        let summary = summarize_ioctl(
            cmd,
            arg,
            cfg.ioctl_decode,
            cfg.max_blob,
            cfg.deref,
            path.map(String::as_str),
        );
        set_decode_target_pid(None);
        summary
    } else {
        format!("cmd=0x{cmd:x}")
    };

    let args = if gpu_related {
        format!(
            "\"{}\" ,{cmd_summary}",
            path.map(String::as_str).unwrap_or("<unknown>")
        )
    } else {
        format!(
            "fd={}{} , {}",
            fd,
            format_fd_suffix(path.map(String::as_str)),
            cmd_summary
        )
    };
    format!("ioctl({args}) = {ret_norm}  /* {elapsed_value} {elapsed_unit} */")
}

fn update_fd_paths(fd_paths: &mut HashMap<i32, String>, state: &SyscallState, ret_norm: i64) {
    match state.nr {
        SYS_OPEN | SYS_OPENAT => {
            if ret_norm >= 0 {
                let fd = ret_norm as i32;
                if let Some(path) = state.path_hint.clone() {
                    fd_paths.insert(fd, path);
                }
            }
        }
        SYS_CLOSE => {
            if ret_norm == 0 {
                fd_paths.remove(&(state.args[0] as i32));
            }
        }
        SYS_DUP => {
            if ret_norm >= 0 {
                duplicate_fd(fd_paths, state.args[0] as i32, ret_norm as i32);
            }
        }
        SYS_DUP2 | SYS_DUP3 => {
            if ret_norm >= 0 {
                duplicate_fd(fd_paths, state.args[0] as i32, ret_norm as i32);
            }
        }
        _ => {}
    }
}

fn update_hidden_fds(
    pid: pid_t,
    state: &SyscallState,
    ret_norm: i64,
    hidden_fds: &mut HashSet<i32>,
) {
    match state.nr {
        SYS_OPEN | SYS_OPENAT => {
            if ret_norm >= 0 && is_cudatrace_output_open(pid, state) {
                hidden_fds.insert(ret_norm as i32);
            }
        }
        SYS_CLOSE => {
            if ret_norm == 0 {
                hidden_fds.remove(&(state.args[0] as i32));
            }
        }
        SYS_DUP => {
            if ret_norm >= 0 && hidden_fds.contains(&(state.args[0] as i32)) {
                hidden_fds.insert(ret_norm as i32);
            }
        }
        SYS_DUP2 | SYS_DUP3 => {
            if ret_norm >= 0 {
                let oldfd = state.args[0] as i32;
                let newfd = ret_norm as i32;
                if hidden_fds.contains(&oldfd) {
                    hidden_fds.insert(newfd);
                } else {
                    hidden_fds.remove(&newfd);
                }
            }
        }
        _ => {}
    }
}

fn seed_fd_state_from_proc(
    pid: pid_t,
    fd_paths: &mut HashMap<i32, String>,
    hidden_fds: &mut HashSet<i32>,
) {
    let dir_path = format!("/proc/{pid}/fd");
    let Ok(entries) = std::fs::read_dir(dir_path) else {
        return;
    };
    for entry in entries.flatten() {
        let fd_raw = entry.file_name();
        let Ok(fd) = fd_raw.to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(link) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let path = link.to_string_lossy().into_owned();
        fd_paths.insert(fd, path.clone());
        if is_cudatrace_output_path(&path) {
            hidden_fds.insert(fd);
        }
    }
}

fn is_cudatrace_output_path(path: &str) -> bool {
    let trimmed = path.trim_end_matches(" (deleted)");
    let base = global().path.as_str();
    let exact_prefix = format!("{base}.tid-");
    if trimmed.contains(&exact_prefix) {
        return true;
    }

    let Some(base_name) = Path::new(base).file_name().and_then(|v| v.to_str()) else {
        return false;
    };
    let short_prefix = format!("{base_name}.tid-");
    trimmed.contains(&short_prefix)
}

fn is_cudatrace_output_open(pid: pid_t, state: &SyscallState) -> bool {
    let _ = pid;
    let Some(path) = state.path_hint.as_deref() else {
        return false;
    };
    is_cudatrace_output_path(path)
}

fn is_hidden_fd_syscall(state: &SyscallState, hidden_fds: &HashSet<i32>) -> bool {
    let fd = match state.nr {
        SYS_READ | SYS_WRITE | SYS_CLOSE | SYS_IOCTL | SYS_FSTAT | SYS_LSEEK | SYS_PREAD64
        | SYS_PWRITE64 | SYS_DUP | SYS_DUP2 | SYS_DUP3 => Some(state.args[0] as i32),
        SYS_MMAP => Some(state.args[4] as i32),
        _ => None,
    };
    fd.map(|f| hidden_fds.contains(&f)).unwrap_or(false)
}

fn duplicate_fd(fd_paths: &mut HashMap<i32, String>, from: i32, to: i32) {
    if let Some(path) = fd_paths.get(&from).cloned() {
        fd_paths.insert(to, path);
    } else {
        fd_paths.remove(&to);
    }
}

fn normalize_ret(ret_raw: i64) -> i64 {
    if is_kernel_error(ret_raw) {
        -1
    } else {
        ret_raw
    }
}

fn is_kernel_error(ret_raw: i64) -> bool {
    (-4095..=-1).contains(&ret_raw)
}

fn duration_for_config(duration: std::time::Duration) -> (u128, &'static str) {
    match global().time_unit {
        TimeUnit::Ns => (duration.as_nanos(), "ns"),
        TimeUnit::Us => (duration.as_micros(), "us"),
    }
}

fn format_fd_suffix(path: Option<&str>) -> String {
    path.map(|p| format!("({p})")).unwrap_or_default()
}

fn indent_ptrace_line(line: String, depth: usize) -> String {
    let cfg = global();
    if !(cfg.trace.cudart || cfg.trace.driver) || depth == 0 {
        line
    } else {
        format!("{}{}", "\t".repeat(depth), line)
    }
}

fn syscall_name(nr: i64) -> String {
    let map = SYSCALL_NAMES.get_or_init(load_syscall_names);
    map.get(&nr)
        .cloned()
        .unwrap_or_else(|| format!("syscall_{nr}"))
}

static SYSCALL_NAMES: OnceLock<HashMap<i64, String>> = OnceLock::new();

fn load_syscall_names() -> HashMap<i64, String> {
    let mut map = HashMap::new();
    let candidates = [
        "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
        "/usr/include/asm/unistd_64.h",
    ];

    for path in candidates {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("#define __NR_") {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(_define_kw) = parts.next() else {
                continue;
            };
            let Some(name_raw) = parts.next() else {
                continue;
            };
            let Some(num_raw) = parts.next() else {
                continue;
            };
            let Some(name) = name_raw.strip_prefix("__NR_") else {
                continue;
            };
            let Ok(nr) = num_raw.parse::<i64>() else {
                continue;
            };
            map.insert(nr, name.to_owned());
        }
        if !map.is_empty() {
            break;
        }
    }

    map
}

fn wifstopped(status: i32) -> bool {
    (status & 0xff) == 0x7f
}

fn wstopsig(status: i32) -> i32 {
    (status >> 8) & 0xff
}

fn wifexited(status: i32) -> bool {
    (status & 0x7f) == 0
}

fn wifsignaled(status: i32) -> bool {
    let sig = status & 0x7f;
    sig != 0 && sig != 0x7f
}

fn ptrace_event(status: i32) -> i32 {
    (status >> 16) & 0xffff
}

fn last_errno() -> i32 {
    // SAFETY: libc provides a thread-local errno location.
    unsafe { *crate::ffi::__errno_location() }
}

fn debug_enabled() -> bool {
    std::env::var("LIB_CUDATRACE_PTRACE_DEBUG")
        .ok()
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        })
        .unwrap_or(false)
}

fn debug_log(msg: &str) {
    if !debug_enabled() {
        return;
    }
    let mut line = String::new();
    let _ = writeln!(&mut line, "[cudatrace-ptrace] {msg}");
    let _ = write_all(crate::ffi::STDERR_FILENO, line.as_bytes());
}

fn debug_log_errno(msg: &str) {
    if !debug_enabled() {
        return;
    }
    debug_log(&format!("{msg}: errno={}", last_errno()));
}

fn log_fgraph_error(msg: &str) {
    let mut line = String::new();
    let _ = writeln!(&mut line, "[cudatrace-fgraph] {msg}");
    let _ = write_all(crate::ffi::STDERR_FILENO, line.as_bytes());
}

fn fatal_exit(msg: &str) -> ! {
    log_fgraph_error(msg);
    std::process::exit(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn open_flags_are_rendered_with_names() {
        let flags = O_RDWR_MASK | O_CREAT_MASK | O_CLOEXEC_MASK;
        let text = format_open_flags(flags);
        assert!(text.contains("O_RDWR"));
        assert!(text.contains("O_CREAT"));
        assert!(text.contains("O_CLOEXEC"));
        assert!(text.contains("(0x"));
    }

    #[test]
    fn mmap_fields_are_rendered_with_names() {
        let prot = PROT_READ_MASK | PROT_WRITE_MASK;
        let flags = MAP_PRIVATE_MASK | MAP_ANONYMOUS_MASK;
        let prot_text = format_mmap_prot(prot);
        let flags_text = format_mmap_flags(flags);
        assert!(prot_text.contains("PROT_READ"));
        assert!(prot_text.contains("PROT_WRITE"));
        assert!(flags_text.contains("MAP_PRIVATE"));
        assert!(flags_text.contains("MAP_ANONYMOUS"));
    }

    #[test]
    fn access_and_seek_are_rendered_with_names() {
        let mode = format_access_mode(R_OK_MASK | W_OK_MASK);
        assert!(mode.contains("R_OK"));
        assert!(mode.contains("W_OK"));

        assert_eq!(format_lseek_whence(SEEK_SET), "SEEK_SET(0x0)");
        assert_eq!(format_lseek_whence(SEEK_CUR), "SEEK_CUR(0x1)");
    }

    #[test]
    fn dirfd_special_value_is_named() {
        assert_eq!(format_dirfd(crate::ffi::AT_FDCWD), "AT_FDCWD");
        assert_eq!(format_dirfd(3), "3");
    }

    #[test]
    fn buffer_helpers_render_hex_and_ascii() {
        assert_eq!(bytes_to_ascii_preview(b"A\n\"\\\t"), "A\\n\\\"\\\\\\t");
    }

    #[test]
    fn buffer_preview_reads_local_memory() {
        let data = *b"hello";
        // SAFETY: getpid has no preconditions.
        let pid = unsafe { crate::ffi::getpid() };
        let preview = format_buffer_preview(pid, data.as_ptr() as u64, data.len() as u64, 5);
        assert_eq!(preview, ", data=\"hello\"");
    }

    #[test]
    fn open_return_includes_path_name() {
        let text = format_open_return(7, Some("/dev/nvidiactl"));
        assert_eq!(text, "7(/dev/nvidiactl)");
        assert_eq!(format_open_return(-1, Some("/dev/null")), "-1");
        assert_eq!(format_open_return(5, Some("<unreadable>")), "5");
    }

    #[test]
    fn internal_syscall_detection_accepts_stack_return_address() {
        // SAFETY: getpid has no preconditions.
        let pid = unsafe { crate::ffi::getpid() };
        let marker =
            internal_syscall_detection_accepts_stack_return_address as *const () as usize as u64;
        let slots = [0_u64, marker, 0_u64, 0_u64];
        let regs = UserRegsStruct {
            rip: 0,
            rsp: slots.as_ptr() as u64,
            ..Default::default()
        };
        let ranges = [(marker.saturating_sub(32), marker.saturating_add(32))];
        assert!(is_internal_syscall(pid, &regs, &ranges));
    }

    #[test]
    fn internal_syscall_detection_rejects_non_matching_stack() {
        // SAFETY: getpid has no preconditions.
        let pid = unsafe { crate::ffi::getpid() };
        let slots = [0x1111_u64, 0x2222_u64, 0x3333_u64, 0x4444_u64];
        let regs = UserRegsStruct {
            rip: 0x5555,
            rsp: slots.as_ptr() as u64,
            ..Default::default()
        };
        let ranges = [(0x6000_u64, 0x7000_u64)];
        assert!(!is_internal_syscall(pid, &regs, &ranges));
    }

    #[test]
    fn output_open_detection_uses_path_hint() {
        let original = global().path.clone();

        let mut state = SyscallState {
            nr: SYS_OPENAT,
            path_hint: Some(format!("{original}.tid-123")),
            ..Default::default()
        };
        assert!(is_cudatrace_output_open(0, &state));

        state.path_hint = Some("/dev/nvidiactl".to_owned());
        assert!(!is_cudatrace_output_open(0, &state));
    }

    #[test]
    fn close_path_hint_can_be_captured_on_entry() {
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let mut args = [0_u64; 6];
        args[0] = file.as_raw_fd() as u64;
        // SAFETY: getpid has no preconditions.
        let pid = unsafe { crate::ffi::getpid() };
        let hint = capture_path_hint(pid, SYS_CLOSE, &args).expect("close path hint");
        assert!(hint.contains("/dev/null"));
    }

    #[test]
    fn fgraph_output_path_uses_required_dimensions() {
        let path = fgraph_output_path("./cudatrace.output", 42, "ioctl", 123456, "cudaMalloc2");
        assert_eq!(
            path,
            "./cudatrace.output.fgraph.tid-42.ts-123456.cudaMalloc2.sys-ioctl.log"
        );
    }

    #[test]
    fn sanitize_file_component_replaces_unsafe_chars() {
        assert_eq!(sanitize_file_component("syscall/name:1"), "syscall_name_1");
    }

    #[test]
    fn sanitize_scope_label_component_falls_back_when_empty() {
        assert_eq!(sanitize_scope_label_component(""), "unknown0");
    }

    #[test]
    fn sanitize_fgraph_trace_output_drops_context_switch_lines() {
        let raw = "\
# tracer: function_graph\n\
 # CPU  DURATION                  FUNCTION CALLS\n\
 ------------------------------------------\n\
  4)    <idle>-0    =>  cudart-1 \n\
  4)   0.301 us    | __x64_sys_ioctl() {\n\
  4)   0.120 us    |   fdget();\n\
";
        let cleaned = sanitize_fgraph_trace_output(raw);
        assert!(!cleaned.contains("# tracer"));
        assert!(!cleaned.contains("=>"));
        assert!(!cleaned.contains("------------------------------------------"));
        let mut lines = cleaned.lines();
        assert_eq!(lines.next().unwrap_or_default(), "__x64_sys_ioctl() {");
        assert_eq!(lines.next().unwrap_or_default(), "\tfdget();");
    }

    #[test]
    fn format_fgraph_syscall_enter_ioctl_contains_key_args() {
        let mut fd_paths = HashMap::new();
        fd_paths.insert(7, "/dev/nvidiactl".to_owned());

        let state = SyscallState {
            nr: SYS_IOCTL,
            args: [7, 0xdeadbeef, 0x1234, 0, 0, 0],
            ..Default::default()
        };
        let line = format_fgraph_syscall_enter(0, &state, &fd_paths);
        assert!(line.contains("ioctl(fd=7"));
        assert!(line.contains("cmd=0xdeadbeef"));
        assert!(line.contains("arg=0x1234"));
        assert!(line.contains("/dev/nvidiactl"));
    }

    #[test]
    fn syscall_graph_function_maps_known_syscall() {
        assert_eq!(
            syscall_graph_function(SYS_IOCTL).as_deref(),
            Some("__x64_sys_ioctl")
        );
    }
}
