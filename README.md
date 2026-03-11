# cudatrace

`cudatrace` is a Rust `cdylib` (`libcudatrace.so`) for `LD_PRELOAD` tracing of:

- CUDA Runtime API (`cudart`)
- CUDA Driver API (`libcuda`)
- Linux syscalls (focus on `ioctl` and GPU file descriptors)

Trace output defaults to per-thread files:

- `./cudatrace.output.tid-<tid>`

## Build

```bash
cargo build
```

The shared library is generated at:

```bash
target/debug/libcudatrace.so
```

## Quick Run (sample/cudart)

```bash
nvcc ./sample/cudart.cu -o ./sample/cudart -cudart=shared
LD_PRELOAD=$PWD/target/debug/libcudatrace.so ./sample/cudart
```

Default output files:

```bash
ls ./cudatrace.output.tid-*
```

## Quick Run (sample/driverapi)

```bash
nvcc -ptx sample/vector_add.cu -o sample/vector_add.ptx
g++ -O2 sample/driverapi.cpp -o sample/driverapi -lcuda
cd sample
LD_PRELOAD=../target/debug/libcudatrace.so ./driverapi
```

## Environment Variables

- `LIB_CUDATRACE_OUTPUT`:
  - `file` (default)
  - `stdout`
- `LIB_CUDATRACE_PATH`:
  - default `./cudatrace.output`
  - `file` mode writes `LIB_CUDATRACE_PATH.tid-<tid>`
- `LIB_CUDATRACE_TRACE`:
  - `all` (default)
  - comma list: `cudart,driver,syscall`
- `LIB_CUDATRACE_IOCTL_DECODE`:
  - `full` (default)
  - `header`
  - `off`
- `LIB_CUDATRACE_MAX_BLOB`:
  - default `256`
- `LIB_CUDATRACE_DEREF`:
  - `on` (default)
  - `off`
- `LIB_CUDATRACE_MAX_DEREF_DEPTH`:
  - max recursive pointer dereference depth
  - default `2`
- `LIB_CUDATRACE_MAX_DEREF_BYTES`:
  - max total bytes copied for recursive dereference per ioctl event
  - default `1024`
- `LIB_CUDATRACE_HEXDUMP_LEN`:
  - max bytes to hex dump for one dereferenced pointer/buffer
  - default `64`
- `LIB_CUDATRACE_TIME_UNIT`:
  - `us` (default)
  - `ns`
- `LIB_CUDATRACE_LEFT_META`:
  - `off` (default)
  - `tid`
  - `ts` / `timestamp`
  - `tid,ts`
  - when enabled, output lines get a left prefix like `tid=12345 ts=1739950000000000us  |  ...`
- `LIB_CUDATRACE_FGRAPH_FUNCS`:
  - optional comma-separated exact function names (case-sensitive)
  - function names must match hooked user-space API symbols (current wrappers)
  - `cudaMallocHost` and `cudaHostAlloc` are treated as aliases for matching
  - when set, function-graph capture is enabled inside the matched function enter/return window
  - each syscall in the window writes one file:
    - `<LIB_CUDATRACE_PATH>.fgraph.tid-<tid>.ts-<entry_us>.<user_func><enter_seq>.sys-<syscall>.log`
    - example: `...ts-1771720262318942.cudaMalloc2.sys-ioctl.log`
  - each fgraph file header includes `syscall_enter=...` with syscall arguments for matching
  - fgraph capture sets `set_graph_function=__x64_sys_<syscall>` to reduce unrelated head/tail kernel frames
  - requires `LIB_CUDATRACE_TRACE` to include `syscall`
  - requires tracefs write permissions (`/sys/kernel/tracing` or `/sys/kernel/debug/tracing`)
  - if this variable is set but tracefs/function_graph is unavailable, the process exits with error
- `LIB_CUDATRACE_FGRAPH_BUFFER_KB`:
  - per-CPU function-graph ring buffer size in KiB
  - default `16384` (16 MiB per CPU)
  - increase this when very long `ioctl` traces appear truncated (e.g. missing upper-half call entries)
- `LIB_CUDATRACE_PTRACE_DEBUG`:
  - optional debug logs (`1/true/yes/on`)

Example:

```bash
LIB_CUDATRACE_OUTPUT=stdout \
LIB_CUDATRACE_TRACE=driver,syscall \
LIB_CUDATRACE_IOCTL_DECODE=header \
LD_PRELOAD=$PWD/target/debug/libcudatrace.so \
./sample/driverapi
```

## ioctl deep-dereference demo (nested pointers)

Build demo:

```bash
cc -O2 sample/ioctl_deref_demo.c -o sample/ioctl_deref_demo
```

Run with cudatrace:

```bash
LIB_CUDATRACE_OUTPUT=stdout \
LIB_CUDATRACE_TRACE=syscall \
LIB_CUDATRACE_IOCTL_DECODE=full \
LIB_CUDATRACE_DEREF=on \
LIB_CUDATRACE_MAX_DEREF_DEPTH=3 \
LIB_CUDATRACE_MAX_DEREF_BYTES=2048 \
LIB_CUDATRACE_HEXDUMP_LEN=64 \
LD_PRELOAD=$PWD/target/debug/libcudatrace.so \
./sample/ioctl_deref_demo
```

Before (`LIB_CUDATRACE_DEREF=off`): only first-level pointers are visible.

```json
"inner":{"cmd_raw":"0xffee11","cmd_name":"UNKNOWN","params_size":32,"paramsPreview":["0x7ff...","0x7ff..."],"preview_truncated":false}
```

After (`LIB_CUDATRACE_DEREF=on`): additional recursive dereference is attached without breaking existing fields.

```json
"inner":{"cmd_raw":"0xffee11","cmd_name":"UNKNOWN","params_size":32,"paramsPreview":["0x7ff...","0x7ff..."],"preview_truncated":false},
"deref":{"ptr":"0x7ff...","depth":0,"read_len":32,"hex":"...","children":[{"ptr":"0x7ff...","depth":1,"read_len":16,"str":"outer-message","status":"ok"}],"status":"ok"}
```

Notes for ptrace syscall tracing:

- `LIB_CUDATRACE_TRACE` contains `syscall` means enabling ptrace syscall capture.
- `ptrace` capture is fused into the same output stream/files.
- Syscall trace output is produced by the built-in `ptrace` path.
- Output format follows syscall line style: `name(args) = ret  /* time */`.
- Requires kernel ptrace permission (Yama/LSM settings may affect availability).

When root permissions are required for tracefs, avoid preloading into `sudo` itself.
Run the target under a root shell so `LD_PRELOAD` applies to the target process:

```bash
sudo sh -c 'LD_PRELOAD=/abs/path/to/libcudatrace.so \
LIB_CUDATRACE_TRACE=cudart,driver,syscall \
LIB_CUDATRACE_FGRAPH_FUNCS=cudaMallocHost \
./sample/cudart'
```
