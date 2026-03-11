use crate::config::{DerefConfig, IoctlDecodeMode};
use crate::decode::ioctl_rm::{decode_nvidia_ioctl, outer_cmd_name};
use crate::decode::ioctl_uvm::{decode_uvm_ioctl, uvm_cmd_name};
use std::cell::Cell;
use std::mem::{MaybeUninit, size_of};

const IOC_NRSHIFT: u64 = 0;
const IOC_TYPESHIFT: u64 = 8;
const IOC_SIZESHIFT: u64 = 16;
const IOC_DIRSHIFT: u64 = 30;

thread_local! {
    static REMOTE_PID_OVERRIDE: Cell<Option<crate::ffi::pid_t>> = const { Cell::new(None) };
}

#[derive(Debug, Clone)]
pub struct DecodeSummary {
    pub legacy: String,
    pub json: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoctlMeta {
    pub raw: crate::ffi::c_ulong,
    pub dir: u8,
    pub ioc_type: u8,
    pub nr: u8,
    pub size: u16,
}

impl IoctlMeta {
    pub fn direction_name(&self) -> &'static str {
        match self.dir {
            0 => "none",
            1 => "write",
            2 => "read",
            3 => "read|write",
            _ => "invalid",
        }
    }
}

pub fn decode_ioctl_cmd(cmd: crate::ffi::c_ulong) -> IoctlMeta {
    let raw = cmd as u64;
    IoctlMeta {
        raw: cmd,
        dir: ((raw >> IOC_DIRSHIFT) & 0x3) as u8,
        ioc_type: ((raw >> IOC_TYPESHIFT) & 0xff) as u8,
        nr: ((raw >> IOC_NRSHIFT) & 0xff) as u8,
        size: ((raw >> IOC_SIZESHIFT) & 0x3fff) as u16,
    }
}

pub fn summarize_ioctl(
    cmd: crate::ffi::c_ulong,
    arg_ptr: *mut crate::ffi::c_void,
    decode_mode: IoctlDecodeMode,
    max_blob: usize,
    deref: DerefConfig,
    fd_path: Option<&str>,
) -> String {
    let meta = decode_ioctl_cmd(cmd);
    let ioc_type = format_ioc_type(meta.ioc_type);
    let ioc_nr = format_ioc_nr(&meta, fd_path);
    let mut out = format!(
        "_IOC(dir={},type={},nr={},size={})",
        meta.direction_name(),
        ioc_type,
        ioc_nr,
        meta.size
    );

    if decode_mode == IoctlDecodeMode::Off {
        return out;
    }

    let decoded = if is_uvm_path(fd_path) {
        decode_uvm_ioctl(&meta, arg_ptr, decode_mode, max_blob)
    } else if is_nvidia_rm_path(fd_path) {
        decode_nvidia_ioctl(&meta, arg_ptr, decode_mode, max_blob, deref)
    } else {
        None
    };

    if let Some(decoded) = decoded {
        let _ = decoded.legacy.is_empty();
        out.push_str(", args=");
        out.push_str(&decoded.json);
    }

    out
}

pub fn set_decode_target_pid(pid: Option<crate::ffi::pid_t>) {
    let _ = REMOTE_PID_OVERRIDE.try_with(|slot| slot.set(pid));
}

fn format_ioc_nr(meta: &IoctlMeta, fd_path: Option<&str>) -> String {
    if is_uvm_path(fd_path) {
        let name = uvm_cmd_name(meta.raw as u64);
        if name != "UNKNOWN" {
            return name.to_owned();
        }
        return meta.nr.to_string();
    }

    if is_nvidia_rm_path(fd_path) {
        let name = outer_cmd_name(meta.nr);
        if name != "UNKNOWN" {
            return name.to_owned();
        }
    }

    meta.nr.to_string()
}

fn is_nvidia_rm_path(path: Option<&str>) -> bool {
    path.map(|p| p.starts_with("/dev/nvidia") && !p.starts_with("/dev/nvidia-uvm"))
        .unwrap_or(false)
}

fn is_uvm_path(path: Option<&str>) -> bool {
    path.map(|p| p.starts_with("/dev/nvidia-uvm"))
        .unwrap_or(false)
}

pub(super) fn format_ioc_type(ioc_type: u8) -> String {
    if ioc_type.is_ascii_graphic() {
        format!("'{}'", ioc_type as char)
    } else {
        format!("0x{ioc_type:x}")
    }
}

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

fn hex_nibble(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => '?',
    }
}

pub(super) unsafe fn read_pod<T: Copy>(remote_addr: usize) -> Option<T> {
    let mut out = MaybeUninit::<T>::uninit();

    let local_iov = crate::ffi::iovec {
        iov_base: out.as_mut_ptr().cast::<crate::ffi::c_void>(),
        iov_len: size_of::<T>(),
    };
    let remote_iov = crate::ffi::iovec {
        iov_base: remote_addr as *mut crate::ffi::c_void,
        iov_len: size_of::<T>(),
    };

    let copied = unsafe {
        crate::ffi::process_vm_readv(decode_target_pid(), &local_iov, 1, &remote_iov, 1, 0)
    };
    if copied == size_of::<T>() as isize {
        Some(unsafe { out.assume_init() })
    } else {
        None
    }
}

pub(super) unsafe fn read_bytes(remote_addr: usize, len: usize) -> Option<Vec<u8>> {
    let mut out = vec![0_u8; len];

    let local_iov = crate::ffi::iovec {
        iov_base: out.as_mut_ptr().cast::<crate::ffi::c_void>(),
        iov_len: len,
    };
    let remote_iov = crate::ffi::iovec {
        iov_base: remote_addr as *mut crate::ffi::c_void,
        iov_len: len,
    };

    let copied = unsafe {
        crate::ffi::process_vm_readv(decode_target_pid(), &local_iov, 1, &remote_iov, 1, 0)
    };
    if copied == len as isize {
        Some(out)
    } else {
        None
    }
}

fn decode_target_pid() -> crate::ffi::pid_t {
    let override_pid = REMOTE_PID_OVERRIDE
        .try_with(|slot| slot.get())
        .ok()
        .flatten();
    override_pid.unwrap_or_else(|| unsafe { crate::ffi::getpid() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DerefConfig;
    use crate::decode::nvidia::{
        NV_ESC_IOCTL_XFER_CMD, NV_ESC_RM_ALLOC_MEMORY, NV_ESC_RM_CONTROL, NV_IOCTL_MAGIC,
        NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_VIDMEM, NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE,
        NV04_CONTROL, Nv0000CtrlClientGetAddrSpaceTypeParams, NvIoctlNvos02ParametersWithFd,
        NvIoctlXfer, NvOs02Parameters, NvOs54Parameters,
    };

    fn encode_ioctl(dir: u8, ioc_type: u8, nr: u8, size: u16) -> crate::ffi::c_ulong {
        (((dir as u64) << 30) | ((ioc_type as u64) << 8) | (nr as u64) | ((size as u64) << 16))
            as crate::ffi::c_ulong
    }

    fn default_deref() -> DerefConfig {
        DerefConfig {
            enabled: true,
            max_depth: 2,
            max_bytes: 1024,
            hexdump_len: 64,
        }
    }

    #[test]
    fn decode_ioc_fields() {
        let cmd = encode_ioctl(3, b'F', NV_ESC_IOCTL_XFER_CMD as u8, 16);
        let meta = decode_ioctl_cmd(cmd);

        assert_eq!(meta.dir, 3);
        assert_eq!(meta.ioc_type, NV_IOCTL_MAGIC);
        assert_eq!(meta.nr, NV_ESC_IOCTL_XFER_CMD as u8);
        assert_eq!(meta.size, 16);
        assert_eq!(meta.direction_name(), "read|write");
    }

    #[test]
    fn summarize_off_mode_stops_at_header() {
        let cmd = encode_ioctl(3, b'F', NV_ESC_IOCTL_XFER_CMD as u8, 16);
        let summary = summarize_ioctl(
            cmd,
            std::ptr::null_mut(),
            IoctlDecodeMode::Off,
            256,
            default_deref(),
            None,
        );
        assert!(summary.contains("_IOC"));
        assert!(!summary.contains("args="));
    }

    #[test]
    fn summarize_reads_xfer_header() {
        let cmd = encode_ioctl(3, b'F', NV_ESC_IOCTL_XFER_CMD as u8, 16);
        let xfer = NvIoctlXfer {
            cmd: 0x36,
            size: 32,
            ptr: 0,
        };

        let summary = summarize_ioctl(
            cmd,
            (&xfer as *const NvIoctlXfer)
                .cast_mut()
                .cast::<crate::ffi::c_void>(),
            IoctlDecodeMode::Header,
            256,
            default_deref(),
            Some("/dev/nvidiactl"),
        );

        assert!(summary.contains("args={"));
        assert!(summary.contains("\"status\":\"header\""));
        assert!(!summary.contains("\"cmd_name\""));
    }

    #[test]
    fn summarize_decodes_known_rm_cmd_via_registry() {
        let cmd = encode_ioctl(3, b'F', NV_ESC_IOCTL_XFER_CMD as u8, 16);
        let known_params = Nv0000CtrlClientGetAddrSpaceTypeParams {
            h_object: 0x1234,
            map_flags: 0x20,
            addr_space_type: NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_VIDMEM,
        };
        let os54 = NvOs54Parameters {
            h_client: 1,
            h_object: 2,
            cmd: NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE,
            flags: 0,
            params: (&known_params as *const Nv0000CtrlClientGetAddrSpaceTypeParams) as u64,
            params_size: size_of::<Nv0000CtrlClientGetAddrSpaceTypeParams>() as u32,
            status: 0,
        };
        let xfer = NvIoctlXfer {
            cmd: NV04_CONTROL,
            size: size_of::<NvOs54Parameters>() as u32,
            ptr: (&os54 as *const NvOs54Parameters) as u64,
        };

        let summary = summarize_ioctl(
            cmd,
            (&xfer as *const NvIoctlXfer)
                .cast_mut()
                .cast::<crate::ffi::c_void>(),
            IoctlDecodeMode::Full,
            256,
            default_deref(),
            Some("/dev/nvidiactl"),
        );

        assert!(summary.contains("nr=NV_ESC_IOCTL_XFER_CMD"));
        assert!(summary.contains("\"addrSpaceTypeName\":\"VIDMEM\""));
        assert!(summary.contains("\"inner\":{"));
    }

    #[test]
    fn summarize_decodes_uvm_known_cmd() {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct UvmParams {
            gpu_uuid: [u8; 16],
            rm_ctrl_fd: i32,
            h_client: u32,
            h_vaspace: u32,
            rm_status: i32,
        }

        let params = UvmParams {
            gpu_uuid: [0x11; 16],
            rm_ctrl_fd: 9,
            h_client: 0xabc,
            h_vaspace: 0xdef,
            rm_status: 0,
        };

        let summary = summarize_ioctl(
            25,
            (&params as *const UvmParams)
                .cast_mut()
                .cast::<crate::ffi::c_void>(),
            IoctlDecodeMode::Full,
            256,
            default_deref(),
            Some("/dev/nvidia-uvm"),
        );

        assert!(summary.contains("nr=UVM_REGISTER_GPU_VASPACE"));
        assert!(summary.contains("args={"));
        assert!(summary.contains("\"hClient\":\"0xabc\""));
        assert!(!summary.contains("\"cmd_name\""));
    }

    #[test]
    fn summarize_decodes_uvm_destroy_range_group() {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct UvmDestroyRangeGroupParams {
            range_group_id: u64,
            rm_status: i32,
        }

        let params = UvmDestroyRangeGroupParams {
            range_group_id: 8,
            rm_status: 0,
        };

        let summary = summarize_ioctl(
            24,
            (&params as *const UvmDestroyRangeGroupParams)
                .cast_mut()
                .cast::<crate::ffi::c_void>(),
            IoctlDecodeMode::Full,
            256,
            default_deref(),
            Some("/dev/nvidia-uvm"),
        );

        assert!(summary.contains("nr=UVM_DESTROY_RANGE_GROUP"));
        assert!(summary.contains("\"rangeGroupId\":8"));
        assert!(!summary.contains("blob_hex"));
    }

    #[test]
    fn summarize_decodes_rm_alloc_memory_wrapper() {
        let cmd = encode_ioctl(
            3,
            b'F',
            NV_ESC_RM_ALLOC_MEMORY as u8,
            size_of::<NvIoctlNvos02ParametersWithFd>() as u16,
        );
        let wrapper = NvIoctlNvos02ParametersWithFd {
            params: NvOs02Parameters {
                h_root: 0x1111,
                h_object_parent: 0x2222,
                h_object_new: 0x3333,
                h_class: 0x71,
                flags: 0x4000_1010,
                p_memory: 0x1234_0000,
                limit: 0x1f_ffff,
                status: 0,
            },
            fd: -1,
        };

        let summary = summarize_ioctl(
            cmd,
            (&wrapper as *const NvIoctlNvos02ParametersWithFd)
                .cast_mut()
                .cast::<crate::ffi::c_void>(),
            IoctlDecodeMode::Full,
            256,
            default_deref(),
            Some("/dev/nvidia0"),
        );

        assert!(summary.contains("args={"));
        assert!(summary.contains("\"api\":\"nv_ioctl_nvos02_parameters_with_fd\""));
        assert!(summary.contains("\"hClass\":\"0x71\""));
        assert!(!summary.contains("blob_hex"));
    }

    #[test]
    fn summarize_adds_recursive_deref_for_unknown_rm_control_params() {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Nested {
            value: u32,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Params {
            inner_ptr: u64,
            marker: u32,
            _pad: u32,
        }

        let nested = Nested { value: 0x11223344 };
        let params = Params {
            inner_ptr: (&nested as *const Nested) as u64,
            marker: 0xaabbccdd,
            _pad: 0,
        };
        let os54 = NvOs54Parameters {
            h_client: 1,
            h_object: 2,
            cmd: 0x00ff_ee11,
            flags: 0,
            params: (&params as *const Params) as u64,
            params_size: size_of::<Params>() as u32,
            status: 0,
        };
        let cmd = encode_ioctl(
            3,
            b'F',
            NV_ESC_RM_CONTROL as u8,
            size_of::<NvOs54Parameters>() as u16,
        );

        let summary = summarize_ioctl(
            cmd,
            (&os54 as *const NvOs54Parameters)
                .cast_mut()
                .cast::<crate::ffi::c_void>(),
            IoctlDecodeMode::Full,
            256,
            default_deref(),
            Some("/dev/nvidiactl"),
        );

        assert!(summary.contains("\"deref\":{"));
        assert!(summary.contains("\"children\":["));
    }
}
