use crate::config::IoctlDecodeMode;
use crate::decode::ioctl::{DecodeSummary, IoctlMeta, hex_bytes, read_bytes, read_pod};
use crate::decode::ioctl_json::{JsonObject, json_quote};
use crate::decode::nvidia::{
    NV_ESC_ALLOC_OS_EVENT, NV_ESC_ATTACH_GPUS_TO_FD, NV_ESC_CARD_INFO, NV_ESC_CHECK_VERSION_STR,
    NV_ESC_EXPORT_TO_DMABUF_FD, NV_ESC_FREE_OS_EVENT, NV_ESC_IOCTL_XFER_CMD, NV_ESC_NUMA_INFO,
    NV_ESC_QUERY_DEVICE_INTR, NV_ESC_REGISTER_FD, NV_ESC_RM_ACCESS_REGISTRY,
    NV_ESC_RM_ADD_VBLANK_CALLBACK, NV_ESC_RM_ALLOC, NV_ESC_RM_ALLOC_CONTEXT_DMA2,
    NV_ESC_RM_ALLOC_MEMORY, NV_ESC_RM_ALLOC_OBJECT, NV_ESC_RM_BIND_CONTEXT_DMA,
    NV_ESC_RM_CONFIG_GET, NV_ESC_RM_CONFIG_GET_EX, NV_ESC_RM_CONFIG_SET, NV_ESC_RM_CONFIG_SET_EX,
    NV_ESC_RM_CONTROL, NV_ESC_RM_DUP_OBJECT, NV_ESC_RM_EXPORT_OBJECT_TO_FD, NV_ESC_RM_FREE,
    NV_ESC_RM_GET_EVENT_DATA, NV_ESC_RM_I2C_ACCESS, NV_ESC_RM_IDLE_CHANNELS,
    NV_ESC_RM_IMPORT_OBJECT_FROM_FD, NV_ESC_RM_LOCKLESS_DIAGNOSTIC, NV_ESC_RM_MAP_MEMORY,
    NV_ESC_RM_MAP_MEMORY_DMA, NV_ESC_RM_SHARE, NV_ESC_RM_UNMAP_MEMORY, NV_ESC_RM_UNMAP_MEMORY_DMA,
    NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO, NV_ESC_RM_VID_HEAP_CONTROL, NV_ESC_SET_NUMA_STATUS,
    NV_ESC_STATUS_CODE, NV_ESC_SYS_PARAMS, NV_ESC_WAIT_OPEN_COMPLETE, NV_IOCTL_MAGIC,
    NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_FABRIC,
    NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_FABRIC_MC,
    NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_INVALID, NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_REGMEM,
    NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_SYSMEM, NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_VIDMEM,
    NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE,
    NV0000_CTRL_CMD_OS_UNIX_GET_CONTROL_FILE_DESCRIPTOR, NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION,
    NV01_ROOT, NV01_ROOT_CLIENT, NV01_ROOT_NON_PRIV, NV04_CONTROL,
    Nv0000CtrlClientGetAddrSpaceTypeParams, Nv0000CtrlOsUnixGetControlFileDescriptorParams,
    Nv0000CtrlSystemGetBuildVersionParams, NvIoctlAllocOsEvent, NvIoctlCardInfo,
    NvIoctlExportToDmaBufFdPrefix, NvIoctlNumaInfo, NvIoctlNvos02ParametersWithFd,
    NvIoctlNvos33ParametersWithFd, NvIoctlQueryDeviceIntr, NvIoctlRegisterFd, NvIoctlRmApiVersion,
    NvIoctlSetNumaStatus, NvIoctlStatusCode, NvIoctlSysParams, NvIoctlWaitOpenComplete,
    NvIoctlXfer, NvOs00Parameters, NvOs02Parameters, NvOs05Parameters, NvOs21Parameters,
    NvOs34Parameters, NvOs54Parameters, NvOs64Parameters,
};
use std::cmp::min;
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::sync::OnceLock;

mod generated_nvidia_ioctl_tables {
    include!(concat!(
        env!("OUT_DIR"),
        "/generated_nvidia_ioctl_tables.rs"
    ));
}

const MAX_NUMA_ADDRESSES: usize = 16;
const MAX_CTRL_LIST_ITEMS: usize = 64;
const MAX_INNER_PREVIEW_WORDS: usize = 8;
const MAX_DEREF_VISITED: usize = 16;
const MAX_DEREF_PTR_CANDIDATES: usize = 8;

const NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS: u32 = 0x0136;
const NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX: u32 = 0x013a;
const NV0000_CTRL_CMD_SYSTEM_GET_FEATURES: u32 = 0x01f0;
const NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE: u32 = 0x027b;
const NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS: u32 = 0x0201;
const NV0000_CTRL_CMD_GPU_GET_ID_INFO: u32 = 0x0202;
const NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2: u32 = 0x0205;
const NV0000_CTRL_CMD_GPU_GET_PROBED_IDS: u32 = 0x0214;
const NV0000_CTRL_CMD_GPU_ATTACH_IDS: u32 = 0x0215;
const NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS: u32 = 0x0288;
const NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO: u32 = 0x0a04;
const NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY: u32 = 0x0d04;
const NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES: u32 = 0x800280;
const NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2: u32 = 0x800292;
const NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE: u32 = 0x800289;
const NV0080_CTRL_CMD_HOST_GET_CAPS_V2: u32 = 0x801402;
const NV0080_CTRL_CMD_FB_GET_CAPS_V2: u32 = 0x801307;
const NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST: u32 = 0x80170d;
const NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL: u32 = 0x801909;
const NV906F_CTRL_GET_CLASS_ENGINEID: u32 = 0x906f0101;
const NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN: u32 = 0xc36f0108;
const NV2080_CTRL_CMD_GPU_GET_INFO_V2: u32 = 0x20800102;
const NV2080_CTRL_CMD_GPU_GET_NAME_STRING: u32 = 0x20800110;
const NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING: u32 = 0x20800111;
const NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO: u32 = 0x20800119;
const NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS: u32 = 0x2080012f;
const NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES: u32 = 0x20800131;
const NV2080_CTRL_CMD_GPU_GET_GID_INFO: u32 = 0x2080014a;
const NV2080_CTRL_CMD_GPU_GET_ENGINES_V2: u32 = 0x20800170;
const NV2080_CTRL_CMD_GR_GET_INFO: u32 = 0x20801201;
const NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER: u32 = 0x2080121b;
const NV2080_CTRL_CMD_GR_GET_CAPS_V2: u32 = 0x20801227;
const NV2080_CTRL_CMD_GR_GET_GPC_MASK: u32 = 0x2080122a;
const NV2080_CTRL_CMD_GR_GET_TPC_MASK: u32 = 0x2080122b;
const NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE: u32 = 0x20801210;
const NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE: u32 = 0x20801218;
const NV2080_CTRL_CMD_FB_GET_INFO_V2: u32 = 0x20801303;
const NV2080_CTRL_CMD_MC_GET_ARCH_INFO: u32 = 0x20801701;
const NV2080_CTRL_CMD_BUS_GET_PCI_INFO: u32 = 0x20801801;
const NV2080_CTRL_CMD_BUS_GET_INFO_V2: u32 = 0x20801823;
const NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO: u32 = 0x20801803;
const NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS: u32 = 0x2080182a;
const NV2080_CTRL_CMD_BUS_GET_C2C_INFO: u32 = 0x2080182b;
const NV2080_CTRL_CMD_PERF_BOOST: u32 = 0x2080200a;
const NV2080_CTRL_CMD_CE_GET_ALL_CAPS: u32 = 0x20802a0a;
const NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS: u32 = 0x20803002;
const NV2080_CTRL_CMD_GSP_GET_FEATURES: u32 = 0x20803601;
const NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO: u32 = 0x20803801;
const NVA06C_CTRL_CMD_GPFIFO_SCHEDULE: u32 = 0xa06c0101;
const NVA06C_CTRL_CMD_SET_TIMESLICE: u32 = 0xa06c0103;
const NVA06C_CTRL_CMD_PREEMPT: u32 = 0xa06c0105;
const NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK: u32 = 0x83de0309;
const NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES: u32 = 0xcb330101;

const NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS: usize = 8;
const NV0000_CTRL_GPU_MAX_ATTACHED_GPUS: usize = 32;
const NV0000_CTRL_GPU_MAX_PROBED_GPUS: usize = 32;
const NV0000_CTRL_GPU_MAX_ACTIVE_DEVICES: usize = 256;
const NV0080_CTRL_GPU_CLASSLIST_MAX_SIZE: usize = 200;
const NV0080_CTRL_FB_CAPS_TBL_SIZE: usize = 3;
const NV0080_CTRL_GR_CAPS_TBL_SIZE: usize = 23;
const NV2080_CTRL_GPU_INFO_MAX_LIST_SIZE: usize = 70;
const NV2080_GPU_MAX_NAME_STRING_LENGTH: usize = 64;
const NV2080_GPU_MAX_ENGINES_LIST_SIZE: usize = 84;
const NV2080_CTRL_GPU_ECC_UNIT_COUNT: usize = 41;
const NV2080_GPU_MAX_GID_LENGTH: usize = 256;
const NV2080_CTRL_FB_INFO_MAX_LIST_SIZE: usize = 128;
const NV2080_CTRL_BUS_INFO_MAX_LIST_SIZE: usize = 52;
const NV2080_CTRL_BUS_MAX_PCI_BARS: usize = 8;
const NV2080_CTRL_PCIE_SUPPORTED_GPU_ATOMICS_OP_TYPE_COUNT: usize = 13;
const NV2080_CTRL_GR_GET_GLOBAL_SM_ORDER_MAX_SM_COUNT: usize = 512;
const NV2080_CTRL_CE_CAPS_TBL_SIZE: usize = 2;
const NV2080_CTRL_MAX_CES: usize = 64;
const NV2080_GSP_MAX_BUILD_VERSION_LENGTH: usize = 64;
const NV2080_CTRL_GRMGR_GR_FS_INFO_MAX_QUERIES: usize = 96;
const NV0000_SYNC_GPU_BOOST_MAX_GROUPS: usize = 16;
const NV_MAX_DEVICES: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
struct RmI2cAccessParams {
    h_client: u32,
    h_device: u32,
    param_size: u32,
    param_struct_ptr: u64,
    status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmIdleChannelsParams {
    h_client: u32,
    h_device: u32,
    h_channel: u32,
    num_channels: u32,
    ph_clients: u64,
    ph_devices: u64,
    ph_channels: u64,
    flags: u32,
    timeout: u32,
    status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmVidHeapControlPrefix {
    h_root: u32,
    h_object_parent: u32,
    function: u32,
    h_vaspace: u32,
    ivc_heap_number: i16,
    _pad0: u16,
    status: u32,
    total: u64,
    free: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmVidHeapAllocSizeData {
    owner: u32,
    h_memory: u32,
    mem_type: u32,
    flags: u32,
    attr: u32,
    format: u32,
    compr_covg: u32,
    zcull_covg: u32,
    partition_stride: u32,
    width: u32,
    height: u32,
    size: u64,
    alignment: u64,
    offset: u64,
    limit: u64,
    address: u64,
    range_begin: u64,
    range_end: u64,
    attr2: u32,
    ctag_offset: u32,
    numa_node: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmVidHeapFreeData {
    owner: u32,
    h_memory: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmVidHeapAllocOsDescData {
    h_memory: u32,
    mem_type: u32,
    flags: u32,
    attr: u32,
    attr2: u32,
    descriptor: u64,
    limit: u64,
    descriptor_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmAccessRegistryParams {
    h_client: u32,
    h_object: u32,
    access_type: u32,
    dev_node_length: u32,
    p_dev_node: u64,
    parm_str_length: u32,
    p_parm_str: u64,
    binary_data_length: u32,
    p_binary_data: u64,
    data: u32,
    entry: u32,
    status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmAllocContextDma2Params {
    h_object_parent: u32,
    h_sub_device: u32,
    h_object_new: u32,
    h_class: u32,
    flags: u32,
    selector: u32,
    h_memory: u32,
    _pad0: u32,
    offset: u64,
    limit: u64,
    status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmGetEventDataParams {
    p_event: u64,
    more_events: u32,
    status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmUnixEvent {
    h_object: u32,
    notify_index: u32,
    info32: u32,
    info16: u16,
    _pad0: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmMapMemoryDmaParams {
    h_client: u32,
    h_device: u32,
    h_dma: u32,
    h_memory: u32,
    offset: u64,
    length: u64,
    flags: u32,
    flags2: u32,
    kind_override: u32,
    _pad0: u32,
    dma_offset: u64,
    status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmUnmapMemoryDmaParams {
    h_client: u32,
    h_device: u32,
    h_dma: u32,
    h_memory: u32,
    flags: u32,
    _pad0: u32,
    dma_offset: u64,
    size: u64,
    status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmBindContextDmaParams {
    h_client: u32,
    h_channel: u32,
    h_ctx_dma: u32,
    status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmDupObjectParams {
    h_client: u32,
    h_parent: u32,
    h_object: u32,
    h_client_src: u32,
    h_object_src: u32,
    flags: u32,
    status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmUpdateDeviceMappingInfoParams {
    h_client: u32,
    h_device: u32,
    h_memory: u32,
    _pad0: u32,
    p_old_cpu_address: u64,
    p_new_cpu_address: u64,
    status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RsAccessMask {
    limbs: [u32; 1],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RsSharePolicy {
    target: u32,
    access_mask: RsAccessMask,
    policy_type: u16,
    action: u8,
    _pad0: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmShareParams {
    h_client: u32,
    h_object: u32,
    share_policy: RsSharePolicy,
    status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RmAddVblankCallbackParams {
    h_client: u32,
    h_device: u32,
    h_vblank: u32,
    _pad0: u32,
    p_proc: u64,
    logical_head: u32,
    _pad1: u32,
    p_parm1: u64,
    p_parm2: u64,
    b_add: u32,
    status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0000CtrlSystemGetFeaturesParams {
    features_mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0000CtrlClientSetInheritedSharePolicyParams {
    share_policy: RsSharePolicy,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0000CtrlGpuGetAttachedIdsParams {
    gpu_ids: [u32; NV0000_CTRL_GPU_MAX_ATTACHED_GPUS],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0000CtrlGpuGetIdInfoParams {
    gpu_id: u32,
    gpu_flags: u32,
    device_instance: u32,
    sub_device_instance: u32,
    sz_name: u64,
    sli_status: u32,
    board_id: u32,
    gpu_instance: u32,
    numa_id: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0000CtrlGpuGetIdInfoV2Params {
    gpu_id: u32,
    gpu_flags: u32,
    device_instance: u32,
    sub_device_instance: u32,
    sli_status: u32,
    board_id: u32,
    gpu_instance: u32,
    numa_id: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0000CtrlGpuGetProbedIdsParams {
    gpu_ids: [u32; NV0000_CTRL_GPU_MAX_PROBED_GPUS],
    excluded_gpu_ids: [u32; NV0000_CTRL_GPU_MAX_PROBED_GPUS],
    gpu_flags: [u32; NV0000_CTRL_GPU_MAX_PROBED_GPUS],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0000CtrlGpuAttachIdsParams {
    gpu_ids: [u32; NV0000_CTRL_GPU_MAX_PROBED_GPUS],
    failed_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0000CtrlGpuActiveDevice {
    gpu_id: u32,
    gpu_instance_id: u32,
    compute_instance_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0000CtrlGpuGetActiveDeviceIdsParams {
    num_devices: u32,
    devices: [Nv0000CtrlGpuActiveDevice; NV0000_CTRL_GPU_MAX_ACTIVE_DEVICES],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0000CtrlSystemGetFabricStatusParams {
    fabric_status: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0000CtrlGpuGetMemopEnableParams {
    enable_mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0000CtrlSystemGetP2PCapsMatrixParams {
    grp_a_count: u32,
    grp_b_count: u32,
    gpu_id_grp_a: [u32; NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS],
    gpu_id_grp_b: [u32; NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS],
    p2p_caps: [[u32; NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS]; NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS],
    a2b_optimal_read_ces:
        [[u32; NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS]; NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS],
    a2b_optimal_write_ces:
        [[u32; NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS]; NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS],
    b2a_optimal_read_ces:
        [[u32; NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS]; NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS],
    b2a_optimal_write_ces:
        [[u32; NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS]; NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0080CtrlHostGetCapsV2Params {
    caps_tbl: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0080CtrlGpuGetNumSubdevicesParams {
    num_sub_devices: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0080CtrlGpuGetClasslistV2Params {
    num_classes: u32,
    class_list: [u32; NV0080_CTRL_GPU_CLASSLIST_MAX_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0080CtrlGpuGetVirtualizationModeParams {
    virtualization_mode: u32,
    is_grid_build: u8,
    _pad0: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0080CtrlFifoGetChannellistParams {
    num_channels: u32,
    p_channel_handle_list: u64,
    p_channel_list: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0080CtrlPerfCudaLimitControlParams {
    b_cuda_limit: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0080CtrlFbGetCapsV2Params {
    caps_tbl: [u8; NV0080_CTRL_FB_CAPS_TBL_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0080CtrlGrGetCapsV2Params {
    caps_tbl: [u8; NV0080_CTRL_GR_CAPS_TBL_SIZE],
    _pad0: u8,
    gr_route_info: Nv2080CtrlGrRouteInfo,
    b_caps_populated: u8,
    _pad1: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv906fCtrlGetClassEngineIdParams {
    h_object: u32,
    class_engine_id: u32,
    class_id: u32,
    engine_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nvc36fCtrlCmdGpfifoGetWorkSubmitTokenParams {
    work_submit_token: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlMcGetArchInfoParams {
    architecture: u32,
    implementation: u32,
    revision: u32,
    sub_revision: u8,
    _pad0: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NvxxxxCtrlXxxInfo {
    index: u32,
    data: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGpuGetInfoV2Params {
    gpu_info_list_size: u32,
    gpu_info_list: [NvxxxxCtrlXxxInfo; NV2080_CTRL_GPU_INFO_MAX_LIST_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGpuGetNameStringParams {
    gpu_name_string_flags: u32,
    gpu_name_string: [u8; NV2080_GPU_MAX_NAME_STRING_LENGTH * 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGpuGetShortNameStringParams {
    gpu_short_name_string: [u8; NV2080_GPU_MAX_NAME_STRING_LENGTH],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGpuGetSimulationInfoParams {
    sim_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGpuGetEnginesV2Params {
    engine_count: u32,
    engine_list: [u32; NV2080_GPU_MAX_ENGINES_LIST_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGpuQueryComputeModeRulesParams {
    rules: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGpuQueryEccExceptionStatus {
    count: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGpuQueryEccUnitStatus {
    enabled: u8,
    scrub_complete: u8,
    supported: u8,
    _pad0: [u8; 5],
    dbe: Nv2080CtrlGpuQueryEccExceptionStatus,
    dbe_non_resettable: Nv2080CtrlGpuQueryEccExceptionStatus,
    sbe: Nv2080CtrlGpuQueryEccExceptionStatus,
    sbe_non_resettable: Nv2080CtrlGpuQueryEccExceptionStatus,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGpuQueryEccStatusParams {
    units: [Nv2080CtrlGpuQueryEccUnitStatus; NV2080_CTRL_GPU_ECC_UNIT_COUNT],
    b_fatal_poison_error: u8,
    uncorrectable_error: u8,
    _pad0: [u8; 2],
    flags: u32,
    gr_route_info: Nv2080CtrlGrRouteInfo,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGpuGetGidInfoParams {
    index: u32,
    flags: u32,
    length: u32,
    data: [u8; NV2080_GPU_MAX_GID_LENGTH],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlFbGetInfoV2Params {
    fb_info_list_size: u32,
    fb_info_list: [NvxxxxCtrlXxxInfo; NV2080_CTRL_FB_INFO_MAX_LIST_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlBusGetInfoV2Params {
    bus_info_list_size: u32,
    bus_info_list: [NvxxxxCtrlXxxInfo; NV2080_CTRL_BUS_INFO_MAX_LIST_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlBusGetC2cInfoParams {
    b_is_link_up: u8,
    b_link_in_hs: u8,
    _pad0: [u8; 2],
    nr_links: u32,
    max_nr_links: u32,
    link_mask: u32,
    per_link_bw_mbps: u32,
    per_link_lane_width: u32,
    remote_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlBusGetPciInfoParams {
    pci_device_id: u32,
    pci_sub_system_id: u32,
    pci_revision_id: u32,
    pci_ext_device_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlBusPciBarInfo {
    flags: u32,
    bar_size: u32,
    bar_size_bytes: u64,
    bar_offset: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlBusGetPciBarInfoParams {
    pci_bar_count: u32,
    _pad0: u32,
    pci_bar_info: [Nv2080CtrlBusPciBarInfo; NV2080_CTRL_BUS_MAX_PCI_BARS],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlBusPcieGpuAtomicOpInfo {
    b_supported: u8,
    _pad0: [u8; 3],
    attributes: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlCmdBusGetPcieSupportedGpuAtomicsParams {
    cap_type: u32,
    dbdf: u32,
    atomic_op:
        [Nv2080CtrlBusPcieGpuAtomicOpInfo; NV2080_CTRL_PCIE_SUPPORTED_GPU_ATOMICS_OP_TYPE_COUNT],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGrRouteInfo {
    flags: u32,
    _pad0: u32,
    route: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGrGetInfoParams {
    gr_info_list_size: u32,
    _pad0: u32,
    gr_info_list: u64,
    gr_route_info: Nv2080CtrlGrRouteInfo,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGrGlobalSmId {
    gpc_id: u16,
    local_tpc_id: u16,
    local_sm_id: u16,
    global_tpc_id: u16,
    virtual_gpc_id: u16,
    migratable_tpc_id: u16,
    ugpu_id: u16,
    physical_cpc_id: u16,
    virtual_tpc_id: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGrGetGlobalSmOrderParams {
    global_sm_id: [Nv2080CtrlGrGlobalSmId; NV2080_CTRL_GR_GET_GLOBAL_SM_ORDER_MAX_SM_COUNT],
    num_sm: u16,
    num_tpc: u16,
    _pad0: u32,
    gr_route_info: Nv2080CtrlGrRouteInfo,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGrGetGpcMaskParams {
    gr_route_info: Nv2080CtrlGrRouteInfo,
    gpc_mask: u32,
    _pad0: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGrGetTpcMaskParams {
    gr_route_info: Nv2080CtrlGrRouteInfo,
    gpc_id: u32,
    tpc_mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGrSetCtxswPreemptionModeParams {
    flags: u32,
    h_channel: u32,
    gfxp_preempt_mode: u32,
    cilp_preempt_mode: u32,
    gr_route_info: Nv2080CtrlGrRouteInfo,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGrGetCtxBufferSizeParams {
    h_channel: u32,
    _pad0: u32,
    total_buffer_size: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlCeGetAllCapsParams {
    caps_tbl: [[u8; NV2080_CTRL_CE_CAPS_TBL_SIZE]; NV2080_CTRL_MAX_CES],
    present: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGspGetFeaturesParams {
    gsp_features: u32,
    b_valid: u8,
    b_default_gsp_rm_gpu: u8,
    _pad0: [u8; 2],
    firmware_version: [u8; NV2080_GSP_MAX_BUILD_VERSION_LENGTH],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGrmgrGrFsInfoQueryParams {
    query_type: u16,
    reserved: [u8; 2],
    status: u32,
    query_data_words: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlGrmgrGetGrFsInfoParams {
    num_queries: u16,
    reserved: [u8; 6],
    queries: [Nv2080CtrlGrmgrGrFsInfoQueryParams; NV2080_CTRL_GRMGR_GR_FS_INFO_MAX_QUERIES],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlNvlinkLinkMask {
    len_masks: u8,
    _pad0: [u8; 7],
    masks: [u64; 1],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlNvlinkGetNvlinkStatusParamsPrefix {
    enabled_link_mask: u32,
    _pad0: u32,
    enabled_links: Nv2080CtrlNvlinkLinkMask,
    b_sublink_state_inst: u8,
    b_nvle_mode_enabled: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NvConfComputeCtrlCmdSystemGetCapabilitiesParams {
    cpu_capability: u8,
    gpus_capability: u8,
    environment: u8,
    cc_feature: u8,
    dev_tools_mode: u8,
    multi_gpu_mode: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0000SyncGpuBoostGroupConfig {
    gpu_count: u32,
    gpu_ids: [u32; NV_MAX_DEVICES],
    boost_group_id: u32,
    b_bridgeless: u8,
    _pad0: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv0000SyncGpuBoostGroupInfoParams {
    group_count: u32,
    boost_groups: [Nv0000SyncGpuBoostGroupConfig; NV0000_SYNC_GPU_BOOST_MAX_GROUPS],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nva06cCtrlGpfifoScheduleParams {
    b_enable: u8,
    b_skip_submit: u8,
    b_skip_enable: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nva06cCtrlTimesliceParams {
    timeslice_us: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nva06cCtrlPreemptParams {
    b_wait: u8,
    b_manual_timeout: u8,
    _pad0: [u8; 2],
    timeout_us: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv83deCtrlDebugSetExceptionMaskParams {
    exception_mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nv2080CtrlPerfBoostParams {
    flags: u32,
    duration: u32,
}

struct KnownRmDecode {
    legacy: String,
    json: String,
}

pub fn decode_nvidia_ioctl(
    meta: &IoctlMeta,
    arg_ptr: *mut c_void,
    decode_mode: IoctlDecodeMode,
    max_blob: usize,
) -> Option<DecodeSummary> {
    if meta.ioc_type != NV_IOCTL_MAGIC {
        return None;
    }

    let mut root = JsonObject::new();

    let mut legacy = String::new();
    if decode_mode == IoctlDecodeMode::Header {
        root.field_str("status", "header");
        return Some(DecodeSummary {
            legacy,
            json: root.finish(),
        });
    }

    if arg_ptr.is_null() {
        root.field_str("status", "arg_null");
        return Some(DecodeSummary {
            legacy,
            json: root.finish(),
        });
    }

    match meta.nr as u32 {
        NV_ESC_IOCTL_XFER_CMD => {
            decode_xfer(arg_ptr, decode_mode, max_blob, &mut legacy, &mut root)
        }
        NV_ESC_RM_CONTROL => decode_rm_control(meta, arg_ptr, max_blob, &mut legacy, &mut root),
        NV_ESC_RM_ALLOC_MEMORY => decode_rm_alloc_memory(meta, arg_ptr, &mut root),
        NV_ESC_RM_ALLOC_OBJECT => decode_rm_alloc_object(meta, arg_ptr, &mut root),
        NV_ESC_RM_ALLOC => decode_rm_alloc(meta, arg_ptr, max_blob, &mut root),
        NV_ESC_RM_FREE => decode_rm_free(meta, arg_ptr, &mut root),
        NV_ESC_RM_MAP_MEMORY => decode_rm_map_memory(meta, arg_ptr, &mut root),
        NV_ESC_RM_UNMAP_MEMORY => decode_rm_unmap_memory(meta, arg_ptr, &mut root),
        NV_ESC_RM_I2C_ACCESS => decode_rm_i2c_access(meta, arg_ptr, &mut root),
        NV_ESC_RM_IDLE_CHANNELS => decode_rm_idle_channels(meta, arg_ptr, &mut root),
        NV_ESC_RM_VID_HEAP_CONTROL => decode_rm_vid_heap_control(meta, arg_ptr, &mut root),
        NV_ESC_RM_ACCESS_REGISTRY => decode_rm_access_registry(meta, arg_ptr, max_blob, &mut root),
        NV_ESC_RM_GET_EVENT_DATA => decode_rm_get_event_data(meta, arg_ptr, &mut root),
        NV_ESC_RM_ALLOC_CONTEXT_DMA2 => decode_rm_alloc_context_dma2(meta, arg_ptr, &mut root),
        NV_ESC_RM_MAP_MEMORY_DMA => decode_rm_map_memory_dma(meta, arg_ptr, &mut root),
        NV_ESC_RM_UNMAP_MEMORY_DMA => decode_rm_unmap_memory_dma(meta, arg_ptr, &mut root),
        NV_ESC_RM_BIND_CONTEXT_DMA => decode_rm_bind_context_dma(meta, arg_ptr, &mut root),
        NV_ESC_RM_DUP_OBJECT => decode_rm_dup_object(meta, arg_ptr, &mut root),
        NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO => {
            decode_rm_update_device_mapping_info(meta, arg_ptr, &mut root)
        }
        NV_ESC_RM_SHARE => decode_rm_share(meta, arg_ptr, &mut root),
        NV_ESC_RM_ADD_VBLANK_CALLBACK => decode_rm_add_vblank_callback(meta, arg_ptr, &mut root),
        NV_ESC_RM_CONFIG_GET
        | NV_ESC_RM_CONFIG_SET
        | NV_ESC_RM_CONFIG_GET_EX
        | NV_ESC_RM_CONFIG_SET_EX
        | NV_ESC_RM_EXPORT_OBJECT_TO_FD
        | NV_ESC_RM_IMPORT_OBJECT_FROM_FD
        | NV_ESC_RM_LOCKLESS_DIAGNOSTIC => decode_rm_opaque(meta, arg_ptr, &mut root),
        NV_ESC_REGISTER_FD => decode_register_fd(meta, arg_ptr, &mut root),
        NV_ESC_ALLOC_OS_EVENT | NV_ESC_FREE_OS_EVENT => {
            decode_alloc_free_os_event(meta, arg_ptr, &mut root)
        }
        NV_ESC_STATUS_CODE => decode_status_code(meta, arg_ptr, &mut root),
        NV_ESC_CHECK_VERSION_STR => decode_rm_api_version(meta, arg_ptr, &mut root),
        NV_ESC_QUERY_DEVICE_INTR => decode_query_device_intr(meta, arg_ptr, &mut root),
        NV_ESC_SYS_PARAMS => decode_sys_params(meta, arg_ptr, &mut root),
        NV_ESC_WAIT_OPEN_COMPLETE => decode_wait_open_complete(meta, arg_ptr, &mut root),
        NV_ESC_NUMA_INFO => decode_numa_info(meta, arg_ptr, &mut root),
        NV_ESC_SET_NUMA_STATUS => decode_set_numa_status(meta, arg_ptr, &mut root),
        NV_ESC_ATTACH_GPUS_TO_FD => decode_attach_gpus(meta, arg_ptr, max_blob, &mut root),
        NV_ESC_EXPORT_TO_DMABUF_FD => decode_export_to_dmabuf(meta, arg_ptr, &mut root),
        NV_ESC_CARD_INFO => decode_card_info(meta, arg_ptr, max_blob, &mut root),
        _ => decode_unknown(meta, arg_ptr, max_blob, &mut root),
    }

    Some(DecodeSummary {
        legacy,
        json: root.finish(),
    })
}

fn decode_xfer(
    arg_ptr: *mut c_void,
    decode_mode: IoctlDecodeMode,
    max_blob: usize,
    legacy: &mut String,
    root: &mut JsonObject,
) {
    let Some(xfer) = (unsafe { read_pod::<NvIoctlXfer>(arg_ptr as usize) }) else {
        legacy.push_str(", xfer=<unreadable>");
        root.field_str("status", "xfer_unreadable");
        return;
    };

    legacy.push_str(&format!(
        ", xfer={{cmd=0x{:x},size={},ptr=0x{:x}}}",
        xfer.cmd, xfer.size, xfer.ptr
    ));

    let mut xfer_json = JsonObject::new();
    xfer_json.field_str("cmd_raw", &format!("0x{:x}", xfer.cmd));
    xfer_json.field_u64("size", xfer.size as u64);
    xfer_json.field_str("ptr", &format!("0x{:x}", xfer.ptr));
    root.field_raw("xfer", &xfer_json.finish());

    if decode_mode != IoctlDecodeMode::Full {
        root.field_str("status", "ok");
        return;
    }

    if xfer.cmd != NV04_CONTROL || xfer.ptr == 0 {
        root.field_str("status", "xfer_non_nvos54");
        return;
    }

    let Some(os54) = (unsafe { read_pod::<NvOs54Parameters>(xfer.ptr as usize) }) else {
        legacy.push_str(", os54=<unreadable>");
        root.field_str("status", "os54_unreadable");
        return;
    };

    decode_nvos54_payload(&os54, max_blob, legacy, root);
}

fn decode_rm_control(
    meta: &IoctlMeta,
    arg_ptr: *mut c_void,
    max_blob: usize,
    legacy: &mut String,
    root: &mut JsonObject,
) {
    match read_checked_pod::<NvOs54Parameters>(meta, arg_ptr) {
        Ok(os54) => decode_nvos54_payload(&os54, max_blob, legacy, root),
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_nvos54_payload(
    os54: &NvOs54Parameters,
    max_blob: usize,
    legacy: &mut String,
    root: &mut JsonObject,
) {
    let cmd_name = rm_control_cmd_name(os54.cmd);
    legacy.push_str(&format!(
        ", os54={{hClient=0x{:x},hObject=0x{:x},cmd=0x{:x}({}),flags=0x{:x},params=0x{:x},paramsSize={},status={}}}",
        os54.h_client,
        os54.h_object,
        os54.cmd,
        cmd_name,
        os54.flags,
        os54.params,
        os54.params_size,
        os54.status
    ));

    let mut os54_json = JsonObject::new();
    os54_json.field_str("hClient", &format!("0x{:x}", os54.h_client));
    os54_json.field_str("hObject", &format!("0x{:x}", os54.h_object));
    os54_json.field_str("cmd_raw", &format!("0x{:x}", os54.cmd));
    os54_json.field_str("cmd_name", &cmd_name);
    os54_json.field_str("flags", &format!("0x{:x}", os54.flags));
    os54_json.field_str("params_ptr", &format!("0x{:x}", os54.params));
    os54_json.field_u64("params_size", os54.params_size as u64);
    os54_json.field_i64("rm_status", os54.status as i64);
    root.field_raw("os54", &os54_json.finish());

    if os54.params == 0 || os54.params_size == 0 {
        root.field_str("status", "ok");
        return;
    }

    if let Some(decoded) =
        decode_known_rm_control(os54.cmd, os54.params as usize, os54.params_size as usize)
    {
        legacy.push_str(&format!(", rmKnown={{{}}}", decoded.legacy));
        root.field_raw("inner", &decoded.json);
        root.field_str("status", "ok");
        return;
    }

    let read_len = min(
        os54.params_size as usize,
        min(max_blob.max(16), MAX_INNER_PREVIEW_WORDS * size_of::<u32>()),
    );
    if read_len == 0 {
        root.field_str("status", "params_empty");
        return;
    }

    let mut inner = JsonObject::new();
    inner.field_str("cmd_raw", &format!("0x{:x}", os54.cmd));
    inner.field_str("cmd_name", &cmd_name);
    inner.field_u64("params_size", os54.params_size as u64);
    if let Some(bytes) = unsafe { read_bytes(os54.params as usize, read_len) } {
        let mut words = Vec::new();
        for chunk in bytes.chunks_exact(size_of::<u32>()) {
            words.push(u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        let params_type_name =
            rm_control_params_type_name(&cmd_name).unwrap_or_else(|| "paramsPreview".to_owned());
        inner.field_raw(&params_type_name, &json_u32_hex_array(&words));
        inner.field_bool("preview_truncated", read_len < os54.params_size as usize);
        root.field_raw("inner", &inner.finish());
        root.field_str("status", "inner_partial");
    } else {
        inner.field_str("preview", "unreadable");
        root.field_raw("inner", &inner.finish());
        root.field_str("status", "params_unreadable");
    }
}

fn decode_rm_alloc_memory(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    let declared = meta.size as usize;

    if declared >= size_of::<NvIoctlNvos02ParametersWithFd>() {
        match read_checked_pod::<NvIoctlNvos02ParametersWithFd>(meta, arg_ptr) {
            Ok(wrapper) => {
                root.field_str("api", "nv_ioctl_nvos02_parameters_with_fd");
                write_nvos02_fields(&wrapper.params, root);
                root.field_i64("fd", wrapper.fd as i64);
                root.field_i64("rmStatus", wrapper.params.status as i64);
                root.field_str("status", "ok");
            }
            Err(err) => root.field_str("status", &err),
        }
        return;
    }

    if declared >= size_of::<NvOs02Parameters>() {
        match read_checked_pod::<NvOs02Parameters>(meta, arg_ptr) {
            Ok(params) => {
                root.field_str("api", "NVOS02");
                write_nvos02_fields(&params, root);
                root.field_i64("rmStatus", params.status as i64);
                root.field_str("status", "ok");
            }
            Err(err) => root.field_str("status", &err),
        }
        return;
    }

    root.field_str(
        "status",
        &format!(
            "size_mismatch(expected>={},actual={declared})",
            size_of::<NvOs02Parameters>()
        ),
    );
}

fn write_nvos02_fields(params: &NvOs02Parameters, root: &mut JsonObject) {
    root.field_str("hRoot", &format!("0x{:x}", params.h_root));
    root.field_str("hObjectParent", &format!("0x{:x}", params.h_object_parent));
    root.field_str("hObjectNew", &format!("0x{:x}", params.h_object_new));
    write_rm_alloc_class(root, params.h_class);
    root.field_str("flags", &format!("0x{:x}", params.flags));
    root.field_str(
        "flagsPhysicality",
        nvos02_flags_physicality_name((params.flags >> 4) & 0x0f),
    );
    root.field_str(
        "flagsLocation",
        nvos02_flags_location_name((params.flags >> 8) & 0x0f),
    );
    root.field_str(
        "flagsCoherency",
        nvos02_flags_coherency_name((params.flags >> 12) & 0x0f),
    );
    root.field_str(
        "flagsAlloc",
        nvos02_flags_alloc_name((params.flags >> 16) & 0x03),
    );
    root.field_bool("flagsGpuCacheable", ((params.flags >> 18) & 0x1) != 0);
    root.field_bool("flagsKernelMapping", ((params.flags >> 19) & 0x1) != 0);
    root.field_str(
        "flagsMapping",
        nvos02_flags_mapping_name((params.flags >> 30) & 0x03),
    );
    root.field_str("pMemory", &format!("0x{:x}", params.p_memory));
    root.field_str("limit", &format!("0x{:x}", params.limit));
}

fn decode_rm_alloc_object(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<NvOs05Parameters>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("api", "NVOS05");
            root.field_str("hRoot", &format!("0x{:x}", params.h_root));
            root.field_str("hObjectParent", &format!("0x{:x}", params.h_object_parent));
            root.field_str("hObjectNew", &format!("0x{:x}", params.h_object_new));
            write_rm_alloc_class(root, params.h_class);
            root.field_i64("rmStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_alloc(meta: &IoctlMeta, arg_ptr: *mut c_void, max_blob: usize, root: &mut JsonObject) {
    let declared = meta.size as usize;

    if declared >= size_of::<NvOs64Parameters>() {
        match read_checked_pod::<NvOs64Parameters>(meta, arg_ptr) {
            Ok(params) => {
                root.field_str("api", "NVOS64");
                root.field_str("hRoot", &format!("0x{:x}", params.h_root));
                root.field_str("hObjectParent", &format!("0x{:x}", params.h_object_parent));
                root.field_str("hObjectNew", &format!("0x{:x}", params.h_object_new));
                write_rm_alloc_class(root, params.h_class);
                root.field_str("pAllocParms", &format!("0x{:x}", params.p_alloc_parms));
                root.field_str(
                    "pRightsRequested",
                    &format!("0x{:x}", params.p_rights_requested),
                );
                root.field_u64("paramsSize", params.params_size as u64);
                root.field_u64("flags", params.flags as u64);
                root.field_i64("rmStatus", params.status as i64);
                decode_alloc_blob(
                    params.p_alloc_parms,
                    params.params_size as usize,
                    max_blob,
                    root,
                );
                root.field_str("status", "ok");
            }
            Err(err) => root.field_str("status", &err),
        }
        return;
    }

    if declared >= size_of::<NvOs21Parameters>() {
        match read_checked_pod::<NvOs21Parameters>(meta, arg_ptr) {
            Ok(params) => {
                root.field_str("api", "NVOS21");
                root.field_str("hRoot", &format!("0x{:x}", params.h_root));
                root.field_str("hObjectParent", &format!("0x{:x}", params.h_object_parent));
                root.field_str("hObjectNew", &format!("0x{:x}", params.h_object_new));
                write_rm_alloc_class(root, params.h_class);
                root.field_str("pAllocParms", &format!("0x{:x}", params.p_alloc_parms));
                root.field_u64("paramsSize", params.params_size as u64);
                root.field_i64("rmStatus", params.status as i64);
                decode_alloc_blob(
                    params.p_alloc_parms,
                    params.params_size as usize,
                    max_blob,
                    root,
                );
                root.field_str("status", "ok");
            }
            Err(err) => root.field_str("status", &err),
        }
        return;
    }

    root.field_str(
        "status",
        &format!(
            "size_mismatch(expected>={},actual={declared})",
            size_of::<NvOs21Parameters>()
        ),
    );
}

fn decode_alloc_blob(params_ptr: u64, params_size: usize, max_blob: usize, root: &mut JsonObject) {
    if params_ptr == 0 || params_size == 0 {
        return;
    }

    let read_len = min(params_size, max_blob.max(16));
    if let Some(bytes) = unsafe { read_bytes(params_ptr as usize, read_len) } {
        root.field_str("allocParamsBlobHex", &hex_bytes(&bytes));
        root.field_bool("allocParamsTruncated", read_len < params_size);
        let cfg = crate::config::global();
        if cfg.should_deref_ioctl("ioctl_rm") {
            let mut visited = Vec::with_capacity(MAX_DEREF_VISITED);
            let mut budget = cfg.ioctl_deref_max_bytes;
            let deref_json = deref_user_pointer(
                params_ptr,
                params_size,
                0,
                cfg.ioctl_deref_max_depth,
                cfg.ioctl_deref_hexdump_len,
                &bytes,
                &mut visited,
                &mut budget,
            );
            root.field_raw("allocParamsDeref", &deref_json);
        }
    } else {
        root.field_str("allocParamsStatus", "unreadable");
    }
}

fn deref_user_pointer(
    addr: u64,
    declared_size: usize,
    depth: usize,
    max_depth: usize,
    hexdump_len: usize,
    prefetched: &[u8],
    visited: &mut Vec<u64>,
    budget: &mut usize,
) -> String {
    let mut out = JsonObject::new();
    out.field_str("addr", &format!("0x{addr:x}"));

    if addr == 0 {
        out.field_str("status", "null");
        return out.finish();
    }
    if depth >= max_depth {
        out.field_str("status", "max_depth_reached");
        return out.finish();
    }
    if visited.contains(&addr) {
        out.field_str("status", "cycle_detected");
        return out.finish();
    }
    if visited.len() >= MAX_DEREF_VISITED {
        out.field_str("status", "visited_limit_exceeded");
        return out.finish();
    }
    if *budget == 0 {
        out.field_str("status", "max_bytes_exceeded");
        return out.finish();
    }

    let cap_len = min(hexdump_len.max(1), *budget);
    let desired_len = if depth == 0 {
        min(prefetched.len(), min(declared_size.max(1), cap_len))
    } else {
        min(declared_size.max(hexdump_len).max(1), cap_len)
    };

    let bytes = if depth == 0 && !prefetched.is_empty() {
        prefetched[..desired_len].to_vec()
    } else if let Some(bytes) = read_bytes_with_fallback(addr as usize, desired_len) {
        bytes
    } else {
        out.field_str("status", "unreadable");
        return out.finish();
    };

    visited.push(addr);
    *budget = budget.saturating_sub(bytes.len());

    out.field_str("status", "ok");
    out.field_u64("readLen", bytes.len() as u64);
    out.field_str("bytesHex", &hex_bytes(&bytes));
    if declared_size > bytes.len() {
        out.field_bool("truncated", true);
    }

    if let Some(text) = parse_printable_c_string(&bytes) {
        out.field_str("string", &text);
    }

    let words: Vec<u64> = bytes
        .chunks_exact(size_of::<u64>())
        .take(MAX_INNER_PREVIEW_WORDS)
        .map(|chunk| {
            let mut raw = [0_u8; size_of::<u64>()];
            raw.copy_from_slice(chunk);
            u64::from_ne_bytes(raw)
        })
        .collect();
    if !words.is_empty() {
        out.field_raw("u64Words", &render_u64_words(&words));
        out.field_raw(
            "ptrFields",
            &render_pointer_fields(
                &words,
                depth + 1,
                max_depth,
                hexdump_len,
                visited,
                budget,
            ),
        );
    }

    let _ = visited.pop();
    out.finish()
}

fn render_u64_words(words: &[u64]) -> String {
    let values = words
        .iter()
        .map(|word| json_quote(&format!("0x{word:x}")))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{values}]")
}

fn render_pointer_fields(
    words: &[u64],
    depth: usize,
    max_depth: usize,
    hexdump_len: usize,
    visited: &mut Vec<u64>,
    budget: &mut usize,
) -> String {
    let mut fields = Vec::new();
    for (idx, word) in words.iter().enumerate() {
        if fields.len() >= MAX_DEREF_PTR_CANDIDATES {
            break;
        }
        if !looks_like_user_pointer(*word) {
            continue;
        }

        let mut item = JsonObject::new();
        item.field_u64("wordIndex", idx as u64);
        item.field_str("addr", &format!("0x{word:x}"));
        let nested = deref_user_pointer(
            *word,
            hexdump_len,
            depth,
            max_depth,
            hexdump_len,
            &[],
            visited,
            budget,
        );
        item.field_raw("value", &nested);
        fields.push(item.finish());
    }
    format!("[{}]", fields.join(","))
}

fn looks_like_user_pointer(value: u64) -> bool {
    value >= 0x1000 && value < 0x0000_8000_0000_0000
}

fn parse_printable_c_string(bytes: &[u8]) -> Option<String> {
    let nul_pos = bytes.iter().position(|b| *b == 0)?;
    if nul_pos == 0 {
        return None;
    }
    let raw = &bytes[..nul_pos];
    if !raw
        .iter()
        .all(|b| b.is_ascii_graphic() || *b == b' ' || *b == b'\t')
    {
        return None;
    }
    std::str::from_utf8(raw).ok().map(ToOwned::to_owned)
}

fn read_bytes_with_fallback(addr: usize, desired_len: usize) -> Option<Vec<u8>> {
    let mut len = desired_len.max(1);
    while len > 0 {
        if let Some(bytes) = unsafe { read_bytes(addr, len) } {
            return Some(bytes);
        }
        len /= 2;
    }
    None
}

fn decode_rm_free(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<NvOs00Parameters>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hRoot", &format!("0x{:x}", params.h_root));
            root.field_str("hObjectParent", &format!("0x{:x}", params.h_object_parent));
            root.field_str("hObjectOld", &format!("0x{:x}", params.h_object_old));
            root.field_i64("rmStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_map_memory(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    let declared = meta.size as usize;
    if declared >= size_of::<NvIoctlNvos33ParametersWithFd>() {
        match read_checked_pod::<NvIoctlNvos33ParametersWithFd>(meta, arg_ptr) {
            Ok(wrapper) => {
                let params = wrapper.params;
                root.field_str("api", "nv_ioctl_nvos33_parameters_with_fd");
                root.field_str("hClient", &format!("0x{:x}", params.h_client));
                root.field_str("hDevice", &format!("0x{:x}", params.h_device));
                root.field_str("hMemory", &format!("0x{:x}", params.h_memory));
                root.field_str("offset", &format!("0x{:x}", params.offset));
                root.field_u64("length", params.length);
                root.field_str(
                    "pLinearAddress",
                    &format!("0x{:x}", params.p_linear_address),
                );
                root.field_u64("flags", params.flags as u64);
                root.field_u64("fd", wrapper.fd as u64);
                root.field_i64("rmStatus", params.status as i64);
                root.field_str("status", "ok");
            }
            Err(err) => root.field_str("status", &err),
        }
        return;
    }

    root.field_str(
        "status",
        &format!(
            "size_mismatch(expected>={},actual={declared})",
            size_of::<NvIoctlNvos33ParametersWithFd>()
        ),
    );
}

fn decode_rm_unmap_memory(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<NvOs34Parameters>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hClient", &format!("0x{:x}", params.h_client));
            root.field_str("hDevice", &format!("0x{:x}", params.h_device));
            root.field_str("hMemory", &format!("0x{:x}", params.h_memory));
            root.field_str(
                "pLinearAddress",
                &format!("0x{:x}", params.p_linear_address),
            );
            root.field_u64("flags", params.flags as u64);
            root.field_i64("rmStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_i2c_access(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<RmI2cAccessParams>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hClient", &format!("0x{:x}", params.h_client));
            root.field_str("hDevice", &format!("0x{:x}", params.h_device));
            root.field_u64("paramSize", params.param_size as u64);
            root.field_str(
                "paramStructPtr",
                &format!("0x{:x}", params.param_struct_ptr),
            );
            root.field_i64("rmStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_idle_channels(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<RmIdleChannelsParams>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hClient", &format!("0x{:x}", params.h_client));
            root.field_str("hDevice", &format!("0x{:x}", params.h_device));
            root.field_str("hChannel", &format!("0x{:x}", params.h_channel));
            root.field_u64("numChannels", params.num_channels as u64);
            root.field_str("phClients", &format!("0x{:x}", params.ph_clients));
            root.field_str("phDevices", &format!("0x{:x}", params.ph_devices));
            root.field_str("phChannels", &format!("0x{:x}", params.ph_channels));
            root.field_str("flags", &format!("0x{:x}", params.flags));
            root.field_u64("timeout", params.timeout as u64);
            root.field_i64("rmStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_vid_heap_control(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<RmVidHeapControlPrefix>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hRoot", &format!("0x{:x}", params.h_root));
            root.field_str("hObjectParent", &format!("0x{:x}", params.h_object_parent));
            root.field_u64("function", params.function as u64);
            root.field_str("functionName", rm_vid_heap_function_name(params.function));
            root.field_str("hVASpace", &format!("0x{:x}", params.h_vaspace));
            root.field_i64("ivcHeapNumber", params.ivc_heap_number as i64);
            root.field_u64("total", params.total);
            root.field_u64("free", params.free);
            root.field_i64("rmStatus", params.status as i64);

            let data_addr = arg_ptr as usize + size_of::<RmVidHeapControlPrefix>();
            match params.function {
                2 => {
                    if let Some(data) = unsafe { read_pod::<RmVidHeapAllocSizeData>(data_addr) } {
                        let mut obj = JsonObject::new();
                        obj.field_u64("owner", data.owner as u64);
                        obj.field_str("hMemory", &format!("0x{:x}", data.h_memory));
                        obj.field_u64("type", data.mem_type as u64);
                        obj.field_str("flags", &format!("0x{:x}", data.flags));
                        obj.field_str("attr", &format!("0x{:x}", data.attr));
                        obj.field_str("format", &format!("0x{:x}", data.format));
                        obj.field_u64("comprCovg", data.compr_covg as u64);
                        obj.field_u64("zcullCovg", data.zcull_covg as u64);
                        obj.field_u64("partitionStride", data.partition_stride as u64);
                        obj.field_u64("width", data.width as u64);
                        obj.field_u64("height", data.height as u64);
                        obj.field_u64("size", data.size);
                        obj.field_u64("alignment", data.alignment);
                        obj.field_str("offset", &format!("0x{:x}", data.offset));
                        obj.field_str("limit", &format!("0x{:x}", data.limit));
                        obj.field_str("address", &format!("0x{:x}", data.address));
                        obj.field_str("rangeBegin", &format!("0x{:x}", data.range_begin));
                        obj.field_str("rangeEnd", &format!("0x{:x}", data.range_end));
                        obj.field_str("attr2", &format!("0x{:x}", data.attr2));
                        obj.field_u64("ctagOffset", data.ctag_offset as u64);
                        obj.field_i64("numaNode", data.numa_node as i64);
                        root.field_raw("allocSize", &obj.finish());
                    }
                }
                3 => {
                    if let Some(data) = unsafe { read_pod::<RmVidHeapFreeData>(data_addr) } {
                        let mut obj = JsonObject::new();
                        obj.field_u64("owner", data.owner as u64);
                        obj.field_str("hMemory", &format!("0x{:x}", data.h_memory));
                        obj.field_str("flags", &format!("0x{:x}", data.flags));
                        root.field_raw("free", &obj.finish());
                    }
                }
                27 => {
                    if let Some(data) = unsafe { read_pod::<RmVidHeapAllocOsDescData>(data_addr) } {
                        let mut obj = JsonObject::new();
                        obj.field_str("hMemory", &format!("0x{:x}", data.h_memory));
                        obj.field_u64("type", data.mem_type as u64);
                        obj.field_str("flags", &format!("0x{:x}", data.flags));
                        obj.field_str("attr", &format!("0x{:x}", data.attr));
                        obj.field_str("attr2", &format!("0x{:x}", data.attr2));
                        obj.field_str("descriptor", &format!("0x{:x}", data.descriptor));
                        obj.field_str("limit", &format!("0x{:x}", data.limit));
                        obj.field_u64("descriptorType", data.descriptor_type as u64);
                        root.field_raw("allocOsDesc", &obj.finish());
                    }
                }
                _ => {}
            }

            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_access_registry(
    meta: &IoctlMeta,
    arg_ptr: *mut c_void,
    max_blob: usize,
    root: &mut JsonObject,
) {
    match read_checked_pod::<RmAccessRegistryParams>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hClient", &format!("0x{:x}", params.h_client));
            root.field_str("hObject", &format!("0x{:x}", params.h_object));
            root.field_u64("accessType", params.access_type as u64);
            root.field_u64("devNodeLength", params.dev_node_length as u64);
            root.field_str("pDevNode", &format!("0x{:x}", params.p_dev_node));
            root.field_u64("parmStrLength", params.parm_str_length as u64);
            root.field_str("pParmStr", &format!("0x{:x}", params.p_parm_str));
            root.field_u64("binaryDataLength", params.binary_data_length as u64);
            root.field_str("pBinaryData", &format!("0x{:x}", params.p_binary_data));
            root.field_u64("data", params.data as u64);
            root.field_u64("entry", params.entry as u64);
            root.field_i64("rmStatus", params.status as i64);

            if params.p_dev_node != 0 && params.dev_node_length > 0 {
                if let Some(text) =
                    read_remote_string(params.p_dev_node, params.dev_node_length as usize, max_blob)
                {
                    root.field_str("devNode", &text);
                }
            }
            if params.p_parm_str != 0 && params.parm_str_length > 0 {
                if let Some(text) =
                    read_remote_string(params.p_parm_str, params.parm_str_length as usize, max_blob)
                {
                    root.field_str("parmStr", &text);
                }
            }
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_get_event_data(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<RmGetEventDataParams>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("pEvent", &format!("0x{:x}", params.p_event));
            root.field_u64("moreEvents", params.more_events as u64);
            root.field_i64("rmStatus", params.status as i64);
            if params.p_event != 0 {
                if let Some(event) = unsafe { read_pod::<RmUnixEvent>(params.p_event as usize) } {
                    let mut obj = JsonObject::new();
                    obj.field_str("hObject", &format!("0x{:x}", event.h_object));
                    obj.field_u64("notifyIndex", event.notify_index as u64);
                    obj.field_u64("info32", event.info32 as u64);
                    obj.field_u64("info16", event.info16 as u64);
                    root.field_raw("event", &obj.finish());
                }
            }
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_alloc_context_dma2(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<RmAllocContextDma2Params>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hObjectParent", &format!("0x{:x}", params.h_object_parent));
            root.field_str("hSubDevice", &format!("0x{:x}", params.h_sub_device));
            root.field_str("hObjectNew", &format!("0x{:x}", params.h_object_new));
            root.field_str("hClass", &format!("0x{:x}", params.h_class));
            root.field_str("flags", &format!("0x{:x}", params.flags));
            root.field_u64("selector", params.selector as u64);
            root.field_str("hMemory", &format!("0x{:x}", params.h_memory));
            root.field_str("offset", &format!("0x{:x}", params.offset));
            root.field_str("limit", &format!("0x{:x}", params.limit));
            root.field_i64("rmStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_map_memory_dma(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<RmMapMemoryDmaParams>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hClient", &format!("0x{:x}", params.h_client));
            root.field_str("hDevice", &format!("0x{:x}", params.h_device));
            root.field_str("hDma", &format!("0x{:x}", params.h_dma));
            root.field_str("hMemory", &format!("0x{:x}", params.h_memory));
            root.field_str("offset", &format!("0x{:x}", params.offset));
            root.field_u64("length", params.length);
            root.field_str("flags", &format!("0x{:x}", params.flags));
            root.field_str("flags2", &format!("0x{:x}", params.flags2));
            root.field_u64("kindOverride", params.kind_override as u64);
            root.field_str("dmaOffset", &format!("0x{:x}", params.dma_offset));
            root.field_i64("rmStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_unmap_memory_dma(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<RmUnmapMemoryDmaParams>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hClient", &format!("0x{:x}", params.h_client));
            root.field_str("hDevice", &format!("0x{:x}", params.h_device));
            root.field_str("hDma", &format!("0x{:x}", params.h_dma));
            root.field_str("hMemory", &format!("0x{:x}", params.h_memory));
            root.field_str("flags", &format!("0x{:x}", params.flags));
            root.field_str("dmaOffset", &format!("0x{:x}", params.dma_offset));
            root.field_u64("size", params.size);
            root.field_i64("rmStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_bind_context_dma(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<RmBindContextDmaParams>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hClient", &format!("0x{:x}", params.h_client));
            root.field_str("hChannel", &format!("0x{:x}", params.h_channel));
            root.field_str("hCtxDma", &format!("0x{:x}", params.h_ctx_dma));
            root.field_i64("rmStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_dup_object(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<RmDupObjectParams>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hClient", &format!("0x{:x}", params.h_client));
            root.field_str("hParent", &format!("0x{:x}", params.h_parent));
            root.field_str("hObject", &format!("0x{:x}", params.h_object));
            root.field_str("hClientSrc", &format!("0x{:x}", params.h_client_src));
            root.field_str("hObjectSrc", &format!("0x{:x}", params.h_object_src));
            root.field_str("flags", &format!("0x{:x}", params.flags));
            root.field_i64("rmStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_update_device_mapping_info(
    meta: &IoctlMeta,
    arg_ptr: *mut c_void,
    root: &mut JsonObject,
) {
    match read_checked_pod::<RmUpdateDeviceMappingInfoParams>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hClient", &format!("0x{:x}", params.h_client));
            root.field_str("hDevice", &format!("0x{:x}", params.h_device));
            root.field_str("hMemory", &format!("0x{:x}", params.h_memory));
            root.field_str(
                "pOldCpuAddress",
                &format!("0x{:x}", params.p_old_cpu_address),
            );
            root.field_str(
                "pNewCpuAddress",
                &format!("0x{:x}", params.p_new_cpu_address),
            );
            root.field_i64("rmStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_share(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<RmShareParams>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hClient", &format!("0x{:x}", params.h_client));
            root.field_str("hObject", &format!("0x{:x}", params.h_object));
            root.field_raw("sharePolicy", &json_share_policy(&params.share_policy));
            root.field_i64("rmStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_add_vblank_callback(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<RmAddVblankCallbackParams>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hClient", &format!("0x{:x}", params.h_client));
            root.field_str("hDevice", &format!("0x{:x}", params.h_device));
            root.field_str("hVblank", &format!("0x{:x}", params.h_vblank));
            root.field_str("pProc", &format!("0x{:x}", params.p_proc));
            root.field_u64("logicalHead", params.logical_head as u64);
            root.field_str("pParm1", &format!("0x{:x}", params.p_parm1));
            root.field_str("pParm2", &format!("0x{:x}", params.p_parm2));
            root.field_bool("add", params.b_add != 0);
            root.field_i64("rmStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_opaque(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    root.field_str("cmdName", outer_cmd_name(meta.nr));
    root.field_u64("declaredSize", meta.size as u64);
    root.field_str("argPtr", &format!("0x{:x}", arg_ptr as usize));
    if meta.size as usize >= size_of::<u32>() {
        let status_addr = arg_ptr as usize + meta.size as usize - size_of::<u32>();
        if let Some(status) = unsafe { read_pod::<u32>(status_addr) } {
            root.field_i64("rmStatusHint", status as i32 as i64);
        }
    }
    root.field_str("status", "opaque");
}

fn decode_register_fd(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<NvIoctlRegisterFd>(meta, arg_ptr) {
        Ok(params) => {
            root.field_i64("ctl_fd", params.ctl_fd as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_alloc_free_os_event(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<NvIoctlAllocOsEvent>(meta, arg_ptr) {
        Ok(params) => {
            root.field_str("hClient", &format!("0x{:x}", params.h_client));
            root.field_str("hDevice", &format!("0x{:x}", params.h_device));
            root.field_u64("fd", params.fd as u64);
            root.field_i64("rmStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_status_code(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<NvIoctlStatusCode>(meta, arg_ptr) {
        Ok(params) => {
            root.field_u64("domain", params.domain as u64);
            root.field_u64("bus", params.bus as u64);
            root.field_u64("slot", params.slot as u64);
            root.field_u64("statusCode", params.status as u64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_rm_api_version(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<NvIoctlRmApiVersion>(meta, arg_ptr) {
        Ok(params) => {
            root.field_u64("cmd", params.cmd as u64);
            root.field_u64("reply", params.reply as u64);
            root.field_str("version", &read_c_string(&params.version_string));
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_query_device_intr(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<NvIoctlQueryDeviceIntr>(meta, arg_ptr) {
        Ok(params) => {
            root.field_u64("intrStatus", params.intr_status as u64);
            root.field_u64("rmStatus", params.status as u64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_sys_params(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<NvIoctlSysParams>(meta, arg_ptr) {
        Ok(params) => {
            root.field_u64("memblock_size", params.memblock_size);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_wait_open_complete(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<NvIoctlWaitOpenComplete>(meta, arg_ptr) {
        Ok(params) => {
            root.field_i64("rc", params.rc as i64);
            root.field_u64("adapterStatus", params.adapter_status as u64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_numa_info(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<NvIoctlNumaInfo>(meta, arg_ptr) {
        Ok(params) => {
            root.field_i64("nid", params.nid as i64);
            root.field_i64("numaStatus", params.status as i64);
            root.field_u64("memblock_size", params.memblock_size);
            root.field_str("numa_mem_addr", &format!("0x{:x}", params.numa_mem_addr));
            root.field_u64("numa_mem_size", params.numa_mem_size);
            root.field_bool("use_auto_online", params.use_auto_online != 0);

            let addr_count = min(
                params.offline_addresses.num_entries as usize,
                params.offline_addresses.addresses.len(),
            );
            let logged = min(addr_count, MAX_NUMA_ADDRESSES);
            root.field_u64("offlineAddressCount", addr_count as u64);
            root.field_raw(
                "offlineAddresses",
                &json_u64_hex_array(&params.offline_addresses.addresses[..logged]),
            );
            root.field_bool("offlineAddressesTruncated", logged < addr_count);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_set_numa_status(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<NvIoctlSetNumaStatus>(meta, arg_ptr) {
        Ok(params) => {
            root.field_i64("numaStatus", params.status as i64);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_attach_gpus(
    meta: &IoctlMeta,
    arg_ptr: *mut c_void,
    max_blob: usize,
    root: &mut JsonObject,
) {
    let declared = meta.size as usize;
    if declared == 0 || (declared % size_of::<u32>()) != 0 {
        root.field_str("status", "size_unknown");
        return;
    }

    let read_len = min(declared, max_blob.max(size_of::<u32>()));
    let Some(bytes) = (unsafe { read_bytes(arg_ptr as usize, read_len) }) else {
        root.field_str("status", "arg_unreadable");
        return;
    };

    let mut ids = Vec::new();
    for chunk in bytes.chunks_exact(4) {
        ids.push(u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }

    root.field_u64("gpu_count", (declared / size_of::<u32>()) as u64);
    root.field_raw("gpu_ids", &json_u32_array(&ids));
    root.field_bool("truncated", read_len < declared);
    root.field_str("status", "ok");
}

fn decode_export_to_dmabuf(meta: &IoctlMeta, arg_ptr: *mut c_void, root: &mut JsonObject) {
    match read_checked_pod::<NvIoctlExportToDmaBufFdPrefix>(meta, arg_ptr) {
        Ok(params) => {
            root.field_i64("fd", params.fd as i64);
            root.field_str("hClient", &format!("0x{:x}", params.h_client));
            root.field_u64("totalObjects", params.total_objects as u64);
            root.field_u64("numObjects", params.num_objects as u64);
            root.field_u64("index", params.index as u64);
            root.field_u64("totalSize", params.total_size);
            root.field_u64("mappingType", params.mapping_type as u64);
            root.field_bool("allowMmap", params.b_allow_mmap != 0);
            root.field_str("status", "ok");
        }
        Err(err) => root.field_str("status", &err),
    }
}

fn decode_card_info(
    meta: &IoctlMeta,
    arg_ptr: *mut c_void,
    max_blob: usize,
    root: &mut JsonObject,
) {
    let declared = meta.size as usize;
    let card_size = size_of::<NvIoctlCardInfo>();
    if declared < card_size {
        root.field_str(
            "status",
            &format!("size_mismatch(expected>={card_size},actual={declared})"),
        );
        return;
    }

    let declared_count = declared / card_size;
    let max_entries = (max_blob / card_size).max(1);
    let read_count = min(declared_count, max_entries);

    let mut decoded = Vec::new();
    for idx in 0..read_count {
        let addr = arg_ptr as usize + idx * card_size;
        let Some(entry) = (unsafe { read_pod::<NvIoctlCardInfo>(addr) }) else {
            break;
        };
        decoded.push(entry);
    }

    if decoded.is_empty() {
        root.field_str("status", "arg_unreadable");
        return;
    }

    let valid_count = decoded.iter().filter(|entry| entry.valid != 0).count();
    root.field_u64("cardCountDeclared", declared_count as u64);
    root.field_u64("cardCountDecoded", decoded.len() as u64);
    root.field_u64("validCount", valid_count as u64);
    root.field_bool("truncated", decoded.len() < declared_count);
    root.field_raw("cards", &json_card_info_array(&decoded));
    root.field_str("status", "ok");
}

fn decode_unknown(meta: &IoctlMeta, arg_ptr: *mut c_void, max_blob: usize, root: &mut JsonObject) {
    let declared = meta.size as usize;
    if declared == 0 {
        root.field_str("status", "unknown_cmd");
        return;
    }

    let read_len = min(declared, max_blob.max(16));
    if let Some(bytes) = unsafe { read_bytes(arg_ptr as usize, read_len) } {
        root.field_str("blob_hex", &hex_bytes(&bytes));
        root.field_bool("truncated", read_len < declared);
        root.field_str("status", "partial");
    } else {
        root.field_str("status", "arg_unreadable");
    }
}

fn read_checked_pod<T: Copy>(meta: &IoctlMeta, arg_ptr: *mut c_void) -> Result<T, String> {
    let expected = size_of::<T>();
    let declared = meta.size as usize;
    if declared > 0 && declared < expected {
        return Err(format!(
            "size_mismatch(expected>={expected},actual={declared})"
        ));
    }

    let Some(value) = (unsafe { read_pod::<T>(arg_ptr as usize) }) else {
        return Err("arg_unreadable".to_owned());
    };
    Ok(value)
}

fn decode_known_rm_control(
    cmd: u32,
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    match cmd {
        NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE => {
            decode_cmd_client_get_addr_space_type(params_addr, params_size)
        }
        NV0000_CTRL_CMD_OS_UNIX_GET_CONTROL_FILE_DESCRIPTOR => {
            decode_cmd_os_unix_get_control_file_descriptor(params_addr, params_size)
        }
        NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION => {
            decode_cmd_system_get_build_version(params_addr, params_size)
        }
        NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY => {
            decode_cmd_client_set_inherited_share_policy(params_addr, params_size)
        }
        NV0000_CTRL_CMD_SYSTEM_GET_FEATURES => {
            decode_cmd_system_get_features(params_addr, params_size)
        }
        NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS => {
            decode_cmd_system_get_fabric_status(params_addr, params_size)
        }
        NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX => {
            decode_cmd_system_get_p2p_caps_matrix(params_addr, params_size)
        }
        NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE => {
            decode_cmd_gpu_get_memop_enable(params_addr, params_size)
        }
        NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS => {
            decode_cmd_gpu_get_attached_ids(params_addr, params_size)
        }
        NV0000_CTRL_CMD_GPU_GET_ID_INFO => decode_cmd_gpu_get_id_info(params_addr, params_size),
        NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 => {
            decode_cmd_gpu_get_id_info_v2(params_addr, params_size)
        }
        NV0000_CTRL_CMD_GPU_GET_PROBED_IDS => {
            decode_cmd_gpu_get_probed_ids(params_addr, params_size)
        }
        NV0000_CTRL_CMD_GPU_ATTACH_IDS => decode_cmd_gpu_attach_ids(params_addr, params_size),
        NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS => {
            decode_cmd_gpu_get_active_device_ids(params_addr, params_size)
        }
        NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO => {
            decode_cmd_sync_gpu_boost_group_info(params_addr, params_size)
        }
        NV0080_CTRL_CMD_HOST_GET_CAPS_V2 => decode_cmd_host_get_caps_v2(params_addr, params_size),
        NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES => {
            decode_cmd_gpu_get_num_subdevices(params_addr, params_size)
        }
        NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2 => {
            decode_cmd_gpu_get_classlist_v2(params_addr, params_size)
        }
        NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE => {
            decode_cmd_gpu_get_virtualization_mode(params_addr, params_size)
        }
        NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST => {
            decode_cmd_fifo_get_channellist(params_addr, params_size)
        }
        NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL => {
            decode_cmd_perf_cuda_limit_set_control(params_addr, params_size)
        }
        NV0080_CTRL_CMD_FB_GET_CAPS_V2 => decode_cmd_fb_get_caps_v2(params_addr, params_size),
        NV906F_CTRL_GET_CLASS_ENGINEID => decode_cmd_class_engine_id(params_addr, params_size),
        NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN => {
            decode_cmd_gpfifo_get_work_submit_token(params_addr, params_size)
        }
        NV2080_CTRL_CMD_MC_GET_ARCH_INFO => decode_cmd_mc_get_arch_info(params_addr, params_size),
        NV2080_CTRL_CMD_GPU_GET_INFO_V2 => decode_cmd_gpu_get_info_v2(params_addr, params_size),
        NV2080_CTRL_CMD_GPU_GET_NAME_STRING => {
            decode_cmd_gpu_get_name_string(params_addr, params_size)
        }
        NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING => {
            decode_cmd_gpu_get_short_name_string(params_addr, params_size)
        }
        NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO => {
            decode_cmd_gpu_get_simulation_info(params_addr, params_size)
        }
        NV2080_CTRL_CMD_GPU_GET_ENGINES_V2 => {
            decode_cmd_gpu_get_engines_v2(params_addr, params_size)
        }
        NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS => {
            decode_cmd_gpu_query_ecc_status(params_addr, params_size)
        }
        NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES => {
            decode_cmd_gpu_query_compute_mode_rules(params_addr, params_size)
        }
        NV2080_CTRL_CMD_GPU_GET_GID_INFO => decode_cmd_gpu_get_gid_info(params_addr, params_size),
        NV2080_CTRL_CMD_FB_GET_INFO_V2 => decode_cmd_fb_get_info_v2(params_addr, params_size),
        NV2080_CTRL_CMD_BUS_GET_PCI_INFO => decode_cmd_bus_get_pci_info(params_addr, params_size),
        NV2080_CTRL_CMD_BUS_GET_INFO_V2 => decode_cmd_bus_get_info_v2(params_addr, params_size),
        NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO => {
            decode_cmd_bus_get_pci_bar_info(params_addr, params_size)
        }
        NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS => {
            decode_cmd_bus_get_pcie_supported_gpu_atomics(params_addr, params_size)
        }
        NV2080_CTRL_CMD_BUS_GET_C2C_INFO => decode_cmd_bus_get_c2c_info(params_addr, params_size),
        NV2080_CTRL_CMD_GR_GET_INFO => decode_cmd_gr_get_info(params_addr, params_size),
        NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER => {
            decode_cmd_gr_get_global_sm_order(params_addr, params_size)
        }
        NV2080_CTRL_CMD_GR_GET_CAPS_V2 => decode_cmd_gr_get_caps_v2(params_addr, params_size),
        NV2080_CTRL_CMD_GR_GET_GPC_MASK => decode_cmd_gr_get_gpc_mask(params_addr, params_size),
        NV2080_CTRL_CMD_GR_GET_TPC_MASK => decode_cmd_gr_get_tpc_mask(params_addr, params_size),
        NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE => {
            decode_cmd_gr_set_ctxsw_preemption_mode(params_addr, params_size)
        }
        NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE => {
            decode_cmd_gr_get_ctx_buffer_size(params_addr, params_size)
        }
        NV2080_CTRL_CMD_CE_GET_ALL_CAPS => decode_cmd_ce_get_all_caps(params_addr, params_size),
        NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS => {
            decode_cmd_nvlink_get_nvlink_status(params_addr, params_size)
        }
        NV2080_CTRL_CMD_GSP_GET_FEATURES => decode_cmd_gsp_get_features(params_addr, params_size),
        NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO => {
            decode_cmd_grmgr_get_gr_fs_info(params_addr, params_size)
        }
        NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES => {
            decode_cmd_conf_compute_get_capabilities(params_addr, params_size)
        }
        NVA06C_CTRL_CMD_GPFIFO_SCHEDULE => decode_cmd_gpfifo_schedule(params_addr, params_size),
        NVA06C_CTRL_CMD_SET_TIMESLICE => decode_cmd_set_timeslice(params_addr, params_size),
        NVA06C_CTRL_CMD_PREEMPT => decode_cmd_preempt(params_addr, params_size),
        NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK => {
            decode_cmd_debug_set_exception_mask(params_addr, params_size)
        }
        NV2080_CTRL_CMD_PERF_BOOST => decode_cmd_perf_boost(params_addr, params_size),
        _ => decode_cmd_nv2080_legacy_generic(cmd, params_addr, params_size),
    }
}

fn decode_cmd_nv2080_legacy_generic(
    cmd: u32,
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    if (cmd >> 16) != 0x2080 {
        return None;
    }

    let interface = ((cmd >> 8) & 0xff) as u8;
    let msg_id = (cmd & 0xff) as u8;
    let Some(interface_name) = nv2080_interface_name(interface) else {
        return None;
    };
    if !interface_name.contains("LEGACY") {
        return None;
    }

    const MAX_WORDS: usize = 64;
    let max_read_len = MAX_WORDS * size_of::<u32>();
    let read_len = min(params_size, max_read_len);
    let cmd_name = rm_control_cmd_name(cmd);
    let params_type_name =
        rm_control_params_type_name(&cmd_name).unwrap_or_else(|| "paramsPreview".to_owned());

    let mut json = JsonObject::new();
    json.field_str("name", &cmd_name);
    json.field_str("interface", interface_name);
    json.field_str("msg_id", &format!("0x{msg_id:02x}"));
    json.field_u64("params_size", params_size as u64);

    if read_len == 0 {
        json.field_str("status", "ok");
        return Some(KnownRmDecode {
            legacy: format!(
                "name={}, interface={}, msgId=0x{msg_id:02x}",
                cmd_name, interface_name
            ),
            json: json.finish(),
        });
    }

    let bytes = unsafe { read_bytes(params_addr, read_len) }?;
    let mut words = Vec::with_capacity(bytes.len() / size_of::<u32>());
    for chunk in bytes.chunks_exact(size_of::<u32>()) {
        words.push(u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }

    if let Some(word0) = words.first() {
        json.field_str("word0", &format!("0x{word0:x}"));
    }
    if let Some(word1) = words.get(1) {
        json.field_str("word1", &format!("0x{word1:x}"));
    }
    if words.len() > 2 {
        json.field_raw(&params_type_name, &json_u32_hex_array(&words));
    }
    json.field_bool("truncated", read_len < params_size);
    json.field_str("status", "ok");

    let mut legacy = format!(
        "name={}, interface={}, msgId=0x{msg_id:02x}",
        cmd_name, interface_name
    );
    if let Some(word0) = words.first() {
        legacy.push_str(&format!(", word0=0x{word0:x}"));
    }
    if let Some(word1) = words.get(1) {
        legacy.push_str(&format!(", word1=0x{word1:x}"));
    }
    if words.len() > 2 {
        legacy.push_str(&format!(", u32Words={}", words.len()));
    }
    if read_len < params_size {
        legacy.push_str(&format!(", truncated({read_len}/{params_size})"));
    }

    Some(KnownRmDecode {
        legacy,
        json: json.finish(),
    })
}

fn decode_cmd_client_get_addr_space_type(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000CtrlClientGetAddrSpaceTypeParams>();
    if params_size < expected {
        let mut json = JsonObject::new();
        json.field_str(
            "status",
            &format!("size_mismatch(expected>={expected},actual={params_size})"),
        );
        return Some(KnownRmDecode {
            legacy: format!(
                "name=NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE, sizeMismatch(expected>={expected}, actual={params_size})"
            ),
            json: json.finish(),
        });
    }

    let params = unsafe { read_pod::<Nv0000CtrlClientGetAddrSpaceTypeParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_str("hObject", &format!("0x{:x}", params.h_object));
    json.field_str("mapFlags", &format!("0x{:x}", params.map_flags));
    json.field_str("addrSpaceType", &format!("0x{:x}", params.addr_space_type));
    json.field_str(
        "addrSpaceTypeName",
        addr_space_type_name(params.addr_space_type),
    );
    json.field_str("status", "ok");

    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE, hObject=0x{:x}, mapFlags=0x{:x}, addrSpaceType=0x{:x}({})",
            params.h_object,
            params.map_flags,
            params.addr_space_type,
            addr_space_type_name(params.addr_space_type)
        ),
        json: json.finish(),
    })
}

fn decode_cmd_os_unix_get_control_file_descriptor(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000CtrlOsUnixGetControlFileDescriptorParams>();
    if params_size < expected {
        let mut json = JsonObject::new();
        json.field_str(
            "status",
            &format!("size_mismatch(expected>={expected},actual={params_size})"),
        );
        return Some(KnownRmDecode {
            legacy: format!(
                "name=NV0000_CTRL_CMD_OS_UNIX_GET_CONTROL_FILE_DESCRIPTOR, sizeMismatch(expected>={expected}, actual={params_size})"
            ),
            json: json.finish(),
        });
    }

    let params =
        unsafe { read_pod::<Nv0000CtrlOsUnixGetControlFileDescriptorParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_i64("fd", params.fd as i64);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0000_CTRL_CMD_OS_UNIX_GET_CONTROL_FILE_DESCRIPTOR, fd={}",
            params.fd
        ),
        json: json.finish(),
    })
}

fn decode_cmd_system_get_build_version(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000CtrlSystemGetBuildVersionParams>();
    if params_size < expected {
        let mut json = JsonObject::new();
        json.field_str(
            "status",
            &format!("size_mismatch(expected>={expected},actual={params_size})"),
        );
        return Some(KnownRmDecode {
            legacy: format!(
                "name=NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION, sizeMismatch(expected>={expected}, actual={params_size})"
            ),
            json: json.finish(),
        });
    }

    let params = unsafe { read_pod::<Nv0000CtrlSystemGetBuildVersionParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_u64("sizeOfStrings", params.size_of_strings as u64);
    json.field_str(
        "pDriverVersionBuffer",
        &format!("0x{:x}", params.p_driver_version_buffer),
    );
    json.field_str(
        "pVersionBuffer",
        &format!("0x{:x}", params.p_version_buffer),
    );
    json.field_str("pTitleBuffer", &format!("0x{:x}", params.p_title_buffer));
    json.field_u64("changelistNumber", params.changelist_number as u64);
    json.field_u64(
        "officialChangelistNumber",
        params.official_changelist_number as u64,
    );
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION, sizeOfStrings={}, pDriverVersionBuffer=0x{:x}, pVersionBuffer=0x{:x}, pTitleBuffer=0x{:x}, changelistNumber={}, officialChangelistNumber={}",
            params.size_of_strings,
            params.p_driver_version_buffer,
            params.p_version_buffer,
            params.p_title_buffer,
            params.changelist_number,
            params.official_changelist_number
        ),
        json: json.finish(),
    })
}

fn known_size_mismatch(name: &str, expected: usize, actual: usize) -> KnownRmDecode {
    let mut json = JsonObject::new();
    json.field_str(
        "status",
        &format!("size_mismatch(expected>={expected},actual={actual})"),
    );
    KnownRmDecode {
        legacy: format!("name={name}, sizeMismatch(expected>={expected}, actual={actual})"),
        json: json.finish(),
    }
}

fn decode_cmd_system_get_fabric_status(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000CtrlSystemGetFabricStatusParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0000CtrlSystemGetFabricStatusParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_u64("fabricStatus", params.fabric_status as u64);
    json.field_str("fabricStatusName", fabric_status_name(params.fabric_status));
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS, fabricStatus={}",
            fabric_status_name(params.fabric_status)
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_memop_enable(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000CtrlGpuGetMemopEnableParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0000CtrlGpuGetMemopEnableParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_str("enableMask", &format!("0x{:x}", params.enable_mask));
    json.field_bool("memOpEnabled", (params.enable_mask & 0x1) != 0);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE, enableMask=0x{:x}",
            params.enable_mask
        ),
        json: json.finish(),
    })
}

fn decode_cmd_system_get_p2p_caps_matrix(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000CtrlSystemGetP2PCapsMatrixParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0000CtrlSystemGetP2PCapsMatrixParams>(params_addr) }?;
    let grp_a_count = min(params.grp_a_count as usize, params.gpu_id_grp_a.len());
    let grp_b_count = min(params.grp_b_count as usize, params.gpu_id_grp_b.len());
    let mut json = JsonObject::new();
    json.field_u64("grpACount", params.grp_a_count as u64);
    json.field_u64("grpBCount", params.grp_b_count as u64);
    json.field_raw(
        "gpuIdGrpA",
        &json_u32_array(&params.gpu_id_grp_a[..grp_a_count]),
    );
    json.field_raw(
        "gpuIdGrpB",
        &json_u32_array(&params.gpu_id_grp_b[..grp_b_count]),
    );
    json.field_raw(
        "p2pCaps",
        &json_u32_matrix(&params.p2p_caps, grp_a_count, grp_b_count),
    );
    json.field_raw(
        "a2bOptimalReadCes",
        &json_u32_matrix(&params.a2b_optimal_read_ces, grp_a_count, grp_b_count),
    );
    json.field_raw(
        "a2bOptimalWriteCes",
        &json_u32_matrix(&params.a2b_optimal_write_ces, grp_a_count, grp_b_count),
    );
    json.field_raw(
        "b2aOptimalReadCes",
        &json_u32_matrix(&params.b2a_optimal_read_ces, grp_a_count, grp_b_count),
    );
    json.field_raw(
        "b2aOptimalWriteCes",
        &json_u32_matrix(&params.b2a_optimal_write_ces, grp_a_count, grp_b_count),
    );
    json.field_bool(
        "truncated",
        grp_a_count < params.grp_a_count as usize || grp_b_count < params.grp_b_count as usize,
    );
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX, grpACount={}, grpBCount={}",
            params.grp_a_count, params.grp_b_count
        ),
        json: json.finish(),
    })
}

fn decode_cmd_client_set_inherited_share_policy(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000CtrlClientSetInheritedSharePolicyParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0000CtrlClientSetInheritedSharePolicyParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_raw("sharePolicy", &json_share_policy(&params.share_policy));
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: "name=NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY".to_owned(),
        json: json.finish(),
    })
}

fn decode_cmd_system_get_features(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000CtrlSystemGetFeaturesParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0000_CTRL_CMD_SYSTEM_GET_FEATURES",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0000CtrlSystemGetFeaturesParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_str("featuresMask", &format!("0x{:x}", params.features_mask));
    json.field_bool("featureSli", (params.features_mask & 0x1) != 0);
    json.field_bool(
        "featureUuidBasedMemSharing",
        (params.features_mask & (1 << 3)) != 0,
    );
    json.field_bool(
        "featureRmTestOnlyCode",
        (params.features_mask & (1 << 4)) != 0,
    );
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0000_CTRL_CMD_SYSTEM_GET_FEATURES, featuresMask=0x{:x}",
            params.features_mask
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_attached_ids(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000CtrlGpuGetAttachedIdsParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0000CtrlGpuGetAttachedIdsParams>(params_addr) }?;
    let ids = valid_gpu_ids(&params.gpu_ids);
    let mut json = JsonObject::new();
    json.field_u64("validCount", ids.len() as u64);
    json.field_raw("gpuIds", &json_u32_array(&ids));
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS, validCount={}",
            ids.len()
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_id_info(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000CtrlGpuGetIdInfoParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0000_CTRL_CMD_GPU_GET_ID_INFO",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0000CtrlGpuGetIdInfoParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_u64("gpuId", params.gpu_id as u64);
    json.field_str("gpuFlags", &format!("0x{:x}", params.gpu_flags));
    json.field_u64("deviceInstance", params.device_instance as u64);
    json.field_u64("subDeviceInstance", params.sub_device_instance as u64);
    json.field_str("szNamePtr", &format!("0x{:x}", params.sz_name));
    json.field_u64("sliStatus", params.sli_status as u64);
    json.field_u64("boardId", params.board_id as u64);
    json.field_u64("gpuInstance", params.gpu_instance as u64);
    json.field_i64("numaId", params.numa_id as i64);
    if params.sz_name != 0 {
        if let Some(name) = read_remote_string(params.sz_name, 128, 128) {
            json.field_str("name", &name);
        }
    }
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0000_CTRL_CMD_GPU_GET_ID_INFO, gpuId={}",
            params.gpu_id
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_id_info_v2(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000CtrlGpuGetIdInfoV2Params>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0000CtrlGpuGetIdInfoV2Params>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_u64("gpuId", params.gpu_id as u64);
    json.field_str("gpuFlags", &format!("0x{:x}", params.gpu_flags));
    json.field_u64("deviceInstance", params.device_instance as u64);
    json.field_u64("subDeviceInstance", params.sub_device_instance as u64);
    json.field_u64("sliStatus", params.sli_status as u64);
    json.field_u64("boardId", params.board_id as u64);
    json.field_u64("gpuInstance", params.gpu_instance as u64);
    json.field_i64("numaId", params.numa_id as i64);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2, gpuId={}",
            params.gpu_id
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_probed_ids(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000CtrlGpuGetProbedIdsParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0000_CTRL_CMD_GPU_GET_PROBED_IDS",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0000CtrlGpuGetProbedIdsParams>(params_addr) }?;
    let gpu_ids = valid_gpu_ids(&params.gpu_ids);
    let excluded_ids = valid_gpu_ids(&params.excluded_gpu_ids);
    let mut json = JsonObject::new();
    json.field_u64("gpuCount", gpu_ids.len() as u64);
    json.field_u64("excludedCount", excluded_ids.len() as u64);
    json.field_raw("gpuIds", &json_u32_array(&gpu_ids));
    json.field_raw("excludedGpuIds", &json_u32_array(&excluded_ids));
    json.field_raw(
        "gpuFlags",
        &json_u32_hex_array(&params.gpu_flags[..gpu_ids.len()]),
    );
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0000_CTRL_CMD_GPU_GET_PROBED_IDS, gpuCount={}",
            gpu_ids.len()
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_attach_ids(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000CtrlGpuAttachIdsParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0000_CTRL_CMD_GPU_ATTACH_IDS",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0000CtrlGpuAttachIdsParams>(params_addr) }?;
    let ids = valid_gpu_ids(&params.gpu_ids);
    let mut json = JsonObject::new();
    json.field_u64("gpuCount", ids.len() as u64);
    json.field_raw("gpuIds", &json_u32_array(&ids));
    json.field_u64("failedId", params.failed_id as u64);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0000_CTRL_CMD_GPU_ATTACH_IDS, gpuCount={}",
            ids.len()
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_active_device_ids(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000CtrlGpuGetActiveDeviceIdsParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0000CtrlGpuGetActiveDeviceIdsParams>(params_addr) }?;
    let count = min(params.num_devices as usize, params.devices.len());
    let mut json = JsonObject::new();
    json.field_u64("numDevices", params.num_devices as u64);
    json.field_raw(
        "devices",
        &json_active_device_array(&params.devices[..count]),
    );
    json.field_bool("truncated", count < params.num_devices as usize);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS, numDevices={}",
            params.num_devices
        ),
        json: json.finish(),
    })
}

fn decode_cmd_sync_gpu_boost_group_info(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0000SyncGpuBoostGroupInfoParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0000SyncGpuBoostGroupInfoParams>(params_addr) }?;
    let count = min(params.group_count as usize, params.boost_groups.len());
    let mut json = JsonObject::new();
    json.field_u64("groupCount", params.group_count as u64);
    json.field_raw(
        "groups",
        &json_sync_gpu_boost_group_array(&params.boost_groups[..count]),
    );
    json.field_bool("truncated", count < params.group_count as usize);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO, groupCount={}",
            params.group_count
        ),
        json: json.finish(),
    })
}

fn decode_cmd_host_get_caps_v2(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0080CtrlHostGetCapsV2Params>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0080_CTRL_CMD_HOST_GET_CAPS_V2",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0080CtrlHostGetCapsV2Params>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_raw("capsTbl", &json_u8_array(&params.caps_tbl));
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: "name=NV0080_CTRL_CMD_HOST_GET_CAPS_V2".to_owned(),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_num_subdevices(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0080CtrlGpuGetNumSubdevicesParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0080CtrlGpuGetNumSubdevicesParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_u64("numSubDevices", params.num_sub_devices as u64);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES, numSubDevices={}",
            params.num_sub_devices
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_classlist_v2(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0080CtrlGpuGetClasslistV2Params>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0080CtrlGpuGetClasslistV2Params>(params_addr) }?;
    let count = min(params.num_classes as usize, params.class_list.len());
    let mut json = JsonObject::new();
    json.field_u64("numClasses", params.num_classes as u64);
    json.field_raw(
        "classList",
        &json_u32_hex_array(&params.class_list[..count]),
    );
    json.field_bool("truncated", count < params.num_classes as usize);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2, numClasses={}",
            params.num_classes
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_virtualization_mode(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0080CtrlGpuGetVirtualizationModeParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0080CtrlGpuGetVirtualizationModeParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_u64("virtualizationMode", params.virtualization_mode as u64);
    json.field_str(
        "virtualizationModeName",
        virtualization_mode_name(params.virtualization_mode),
    );
    json.field_bool("isGridBuild", params.is_grid_build != 0);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE, mode={}",
            params.virtualization_mode
        ),
        json: json.finish(),
    })
}

fn decode_cmd_fifo_get_channellist(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0080CtrlFifoGetChannellistParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0080CtrlFifoGetChannellistParams>(params_addr) }?;
    let count = min(params.num_channels as usize, MAX_CTRL_LIST_ITEMS);
    let mut handles = Vec::new();
    let mut channels = Vec::new();
    if params.p_channel_handle_list != 0 && count > 0 {
        if let Some(bytes) = unsafe {
            read_bytes(
                params.p_channel_handle_list as usize,
                count * size_of::<u32>(),
            )
        } {
            for chunk in bytes.chunks_exact(size_of::<u32>()) {
                handles.push(u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
        }
    }
    if params.p_channel_list != 0 && count > 0 {
        if let Some(bytes) =
            unsafe { read_bytes(params.p_channel_list as usize, count * size_of::<u32>()) }
        {
            for chunk in bytes.chunks_exact(size_of::<u32>()) {
                channels.push(u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
        }
    }

    let mut json = JsonObject::new();
    json.field_u64("numChannels", params.num_channels as u64);
    json.field_str(
        "pChannelHandleList",
        &format!("0x{:x}", params.p_channel_handle_list),
    );
    json.field_str("pChannelList", &format!("0x{:x}", params.p_channel_list));
    if !handles.is_empty() {
        json.field_raw("channelHandleList", &json_u32_hex_array(&handles));
    }
    if !channels.is_empty() {
        json.field_raw("channelIdList", &json_u32_hex_array(&channels));
    }
    json.field_bool("truncated", count < params.num_channels as usize);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST, numChannels={}",
            params.num_channels
        ),
        json: json.finish(),
    })
}

fn decode_cmd_perf_cuda_limit_set_control(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0080CtrlPerfCudaLimitControlParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0080CtrlPerfCudaLimitControlParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_bool("cudaLimit", params.b_cuda_limit != 0);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL, cudaLimit={}",
            params.b_cuda_limit
        ),
        json: json.finish(),
    })
}

fn decode_cmd_fb_get_caps_v2(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0080CtrlFbGetCapsV2Params>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV0080_CTRL_CMD_FB_GET_CAPS_V2",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0080CtrlFbGetCapsV2Params>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_raw("capsTbl", &json_u8_hex_array(&params.caps_tbl));
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: "name=NV0080_CTRL_CMD_FB_GET_CAPS_V2".to_owned(),
        json: json.finish(),
    })
}

fn decode_cmd_class_engine_id(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv906fCtrlGetClassEngineIdParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV906F_CTRL_GET_CLASS_ENGINEID",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv906fCtrlGetClassEngineIdParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_str("hObject", &format!("0x{:x}", params.h_object));
    json.field_u64("classEngineId", params.class_engine_id as u64);
    json.field_str("classId", &format!("0x{:x}", params.class_id));
    json.field_str("engineId", &format!("0x{:x}", params.engine_id));
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV906F_CTRL_GET_CLASS_ENGINEID, hObject=0x{:x}",
            params.h_object
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpfifo_get_work_submit_token(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nvc36fCtrlCmdGpfifoGetWorkSubmitTokenParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nvc36fCtrlCmdGpfifoGetWorkSubmitTokenParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_u64("workSubmitToken", params.work_submit_token as u64);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN, token={}",
            params.work_submit_token
        ),
        json: json.finish(),
    })
}

fn decode_cmd_mc_get_arch_info(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlMcGetArchInfoParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_MC_GET_ARCH_INFO",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlMcGetArchInfoParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_str("architecture", &format!("0x{:x}", params.architecture));
    json.field_str("implementation", &format!("0x{:x}", params.implementation));
    json.field_str("revision", &format!("0x{:x}", params.revision));
    json.field_u64("subRevision", params.sub_revision as u64);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_MC_GET_ARCH_INFO, arch=0x{:x}",
            params.architecture
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_info_v2(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGpuGetInfoV2Params>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GPU_GET_INFO_V2",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGpuGetInfoV2Params>(params_addr) }?;
    let count = min(
        params.gpu_info_list_size as usize,
        params.gpu_info_list.len(),
    );
    let mut json = JsonObject::new();
    json.field_u64("gpuInfoListSize", params.gpu_info_list_size as u64);
    json.field_raw(
        "gpuInfoList",
        &json_xxx_info_array(&params.gpu_info_list[..count]),
    );
    json.field_bool("truncated", count < params.gpu_info_list_size as usize);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GPU_GET_INFO_V2, gpuInfoListSize={}",
            params.gpu_info_list_size
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_name_string(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGpuGetNameStringParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GPU_GET_NAME_STRING",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGpuGetNameStringParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_str(
        "gpuNameStringFlags",
        &format!("0x{:x}", params.gpu_name_string_flags),
    );
    let name = if (params.gpu_name_string_flags & 0x1) != 0 {
        read_utf16le_c_string(&params.gpu_name_string)
    } else {
        read_c_string(&params.gpu_name_string[..NV2080_GPU_MAX_NAME_STRING_LENGTH])
    };
    json.field_str("name", &name);
    json.field_str(
        "encoding",
        if (params.gpu_name_string_flags & 0x1) != 0 {
            "UTF16"
        } else {
            "ASCII"
        },
    );
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GPU_GET_NAME_STRING, name=\"{}\"",
            name
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_short_name_string(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGpuGetShortNameStringParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGpuGetShortNameStringParams>(params_addr) }?;
    let name = read_c_string(&params.gpu_short_name_string);
    let mut json = JsonObject::new();
    json.field_str("name", &name);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING, name=\"{}\"",
            name
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_simulation_info(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGpuGetSimulationInfoParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGpuGetSimulationInfoParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_u64("type", params.sim_type as u64);
    json.field_str("typeName", simulation_info_type_name(params.sim_type));
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO, type={}",
            simulation_info_type_name(params.sim_type)
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_engines_v2(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGpuGetEnginesV2Params>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GPU_GET_ENGINES_V2",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGpuGetEnginesV2Params>(params_addr) }?;
    let count = min(params.engine_count as usize, params.engine_list.len());
    let mut json = JsonObject::new();
    json.field_u64("engineCount", params.engine_count as u64);
    json.field_raw(
        "engineList",
        &json_u32_hex_array(&params.engine_list[..count]),
    );
    json.field_bool("truncated", count < params.engine_count as usize);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GPU_GET_ENGINES_V2, engineCount={}",
            params.engine_count
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_query_compute_mode_rules(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGpuQueryComputeModeRulesParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGpuQueryComputeModeRulesParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_u64("rules", params.rules as u64);
    json.field_str("rulesName", compute_mode_rules_name(params.rules));
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES, rules={}",
            compute_mode_rules_name(params.rules)
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_query_ecc_status(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGpuQueryEccStatusParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGpuQueryEccStatusParams>(params_addr) }?;
    let mut enabled_units = 0usize;
    let mut supported_units = 0usize;
    let mut scrub_complete_units = 0usize;
    let mut dbe_total = 0u64;
    let mut sbe_total = 0u64;
    let mut sampled = Vec::new();
    let mut non_zero_units = 0usize;
    for (idx, unit) in params.units.iter().enumerate() {
        if unit.enabled != 0 {
            enabled_units += 1;
        }
        if unit.supported != 0 {
            supported_units += 1;
        }
        if unit.scrub_complete != 0 {
            scrub_complete_units += 1;
        }
        dbe_total = dbe_total.saturating_add(unit.dbe.count);
        sbe_total = sbe_total.saturating_add(unit.sbe.count);
        let non_zero =
            unit.enabled != 0 || unit.supported != 0 || unit.dbe.count != 0 || unit.sbe.count != 0;
        if non_zero {
            non_zero_units += 1;
            if sampled.len() < MAX_CTRL_LIST_ITEMS {
                sampled.push((idx as u32, unit));
            }
        }
    }

    let mut json = JsonObject::new();
    json.field_u64("unitCount", params.units.len() as u64);
    json.field_u64("enabledUnits", enabled_units as u64);
    json.field_u64("supportedUnits", supported_units as u64);
    json.field_u64("scrubCompleteUnits", scrub_complete_units as u64);
    json.field_u64("dbeTotal", dbe_total);
    json.field_u64("sbeTotal", sbe_total);
    json.field_bool("fatalPoisonError", params.b_fatal_poison_error != 0);
    json.field_u64("uncorrectableError", params.uncorrectable_error as u64);
    json.field_str("flags", &format!("0x{:x}", params.flags));
    let mut route = JsonObject::new();
    route.field_str("flags", &format!("0x{:x}", params.gr_route_info.flags));
    route.field_str("route", &format!("0x{:x}", params.gr_route_info.route));
    json.field_raw("grRouteInfo", &route.finish());
    json.field_raw("unitSample", &json_ecc_unit_sample_array(&sampled));
    json.field_bool("sampleTruncated", sampled.len() < non_zero_units);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS, enabledUnits={}, dbeTotal={}, sbeTotal={}",
            enabled_units, dbe_total, sbe_total
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gpu_get_gid_info(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGpuGetGidInfoParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GPU_GET_GID_INFO",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGpuGetGidInfoParams>(params_addr) }?;
    let len = min(params.length as usize, params.data.len());
    let mut json = JsonObject::new();
    json.field_u64("index", params.index as u64);
    json.field_str("flags", &format!("0x{:x}", params.flags));
    json.field_u64("length", params.length as u64);
    if (params.flags & 0x2) == 0 {
        let text = String::from_utf8_lossy(&params.data[..len]).into_owned();
        json.field_str("gid", text.trim_matches(char::from(0)));
    } else {
        json.field_raw("gidBytes", &json_u8_array(&params.data[..len]));
    }
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GPU_GET_GID_INFO, length={}",
            params.length
        ),
        json: json.finish(),
    })
}

fn decode_cmd_fb_get_info_v2(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlFbGetInfoV2Params>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_FB_GET_INFO_V2",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlFbGetInfoV2Params>(params_addr) }?;
    let count = min(params.fb_info_list_size as usize, params.fb_info_list.len());
    let mut json = JsonObject::new();
    json.field_u64("fbInfoListSize", params.fb_info_list_size as u64);
    json.field_raw(
        "fbInfoList",
        &json_xxx_info_array(&params.fb_info_list[..count]),
    );
    json.field_bool("truncated", count < params.fb_info_list_size as usize);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_FB_GET_INFO_V2, fbInfoListSize={}",
            params.fb_info_list_size
        ),
        json: json.finish(),
    })
}

fn decode_cmd_bus_get_pci_info(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlBusGetPciInfoParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_BUS_GET_PCI_INFO",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlBusGetPciInfoParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_str("pciDeviceId", &format!("0x{:x}", params.pci_device_id));
    json.field_str(
        "pciSubSystemId",
        &format!("0x{:x}", params.pci_sub_system_id),
    );
    json.field_str("pciRevisionId", &format!("0x{:x}", params.pci_revision_id));
    json.field_str(
        "pciExtDeviceId",
        &format!("0x{:x}", params.pci_ext_device_id),
    );
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: "name=NV2080_CTRL_CMD_BUS_GET_PCI_INFO".to_owned(),
        json: json.finish(),
    })
}

fn decode_cmd_bus_get_info_v2(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlBusGetInfoV2Params>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_BUS_GET_INFO_V2",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlBusGetInfoV2Params>(params_addr) }?;
    let count = min(
        params.bus_info_list_size as usize,
        params.bus_info_list.len(),
    );
    let mut json = JsonObject::new();
    json.field_u64("busInfoListSize", params.bus_info_list_size as u64);
    json.field_raw(
        "busInfoList",
        &json_xxx_info_array(&params.bus_info_list[..count]),
    );
    json.field_bool("truncated", count < params.bus_info_list_size as usize);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_BUS_GET_INFO_V2, busInfoListSize={}",
            params.bus_info_list_size
        ),
        json: json.finish(),
    })
}

fn decode_cmd_bus_get_pci_bar_info(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlBusGetPciBarInfoParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlBusGetPciBarInfoParams>(params_addr) }?;
    let count = min(params.pci_bar_count as usize, params.pci_bar_info.len());
    let mut json = JsonObject::new();
    json.field_u64("pciBarCount", params.pci_bar_count as u64);
    json.field_raw(
        "pciBarInfo",
        &json_pci_bar_info_array(&params.pci_bar_info[..count]),
    );
    json.field_bool("truncated", count < params.pci_bar_count as usize);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO, pciBarCount={}",
            params.pci_bar_count
        ),
        json: json.finish(),
    })
}

fn decode_cmd_bus_get_pcie_supported_gpu_atomics(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlCmdBusGetPcieSupportedGpuAtomicsParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS",
            expected,
            params_size,
        ));
    }
    let params =
        unsafe { read_pod::<Nv2080CtrlCmdBusGetPcieSupportedGpuAtomicsParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_u64("capType", params.cap_type as u64);
    json.field_str("dbdf", &format!("0x{:x}", params.dbdf));
    json.field_raw("atomicOp", &json_atomic_op_array(&params.atomic_op));
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: "name=NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS".to_owned(),
        json: json.finish(),
    })
}

fn decode_cmd_bus_get_c2c_info(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlBusGetC2cInfoParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_BUS_GET_C2C_INFO",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlBusGetC2cInfoParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_bool("isLinkUp", params.b_is_link_up != 0);
    json.field_bool("linkInHighSpeed", params.b_link_in_hs != 0);
    json.field_u64("nrLinks", params.nr_links as u64);
    json.field_u64("maxNrLinks", params.max_nr_links as u64);
    json.field_str("linkMask", &format!("0x{:x}", params.link_mask));
    json.field_u64("perLinkBwMBps", params.per_link_bw_mbps as u64);
    json.field_u64("perLinkLaneWidth", params.per_link_lane_width as u64);
    json.field_u64("remoteType", params.remote_type as u64);
    json.field_str("remoteTypeName", c2c_remote_type_name(params.remote_type));
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_BUS_GET_C2C_INFO, isLinkUp={}, nrLinks={}",
            params.b_is_link_up != 0,
            params.nr_links
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gr_get_info(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGrGetInfoParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GR_GET_INFO",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGrGetInfoParams>(params_addr) }?;
    let mut entries = Vec::new();
    let count = min(params.gr_info_list_size as usize, MAX_CTRL_LIST_ITEMS);
    if params.gr_info_list != 0 && count > 0 {
        if let Some(bytes) = unsafe {
            read_bytes(
                params.gr_info_list as usize,
                count * size_of::<NvxxxxCtrlXxxInfo>(),
            )
        } {
            for chunk in bytes.chunks_exact(size_of::<NvxxxxCtrlXxxInfo>()) {
                entries.push(NvxxxxCtrlXxxInfo {
                    index: u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                    data: u32::from_ne_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
                });
            }
        }
    }
    let mut json = JsonObject::new();
    json.field_u64("grInfoListSize", params.gr_info_list_size as u64);
    json.field_str("grInfoListPtr", &format!("0x{:x}", params.gr_info_list));
    json.field_raw("grInfoList", &json_xxx_info_array(&entries));
    json.field_bool("truncated", count < params.gr_info_list_size as usize);
    let mut route = JsonObject::new();
    route.field_str("flags", &format!("0x{:x}", params.gr_route_info.flags));
    route.field_str("route", &format!("0x{:x}", params.gr_route_info.route));
    json.field_raw("grRouteInfo", &route.finish());
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GR_GET_INFO, grInfoListSize={}",
            params.gr_info_list_size
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gr_get_global_sm_order(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGrGetGlobalSmOrderParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGrGetGlobalSmOrderParams>(params_addr) }?;
    let count = min(params.num_sm as usize, params.global_sm_id.len());
    let sampled = min(count, MAX_CTRL_LIST_ITEMS);
    let mut json = JsonObject::new();
    json.field_u64("numSm", params.num_sm as u64);
    json.field_u64("numTpc", params.num_tpc as u64);
    json.field_raw(
        "globalSmId",
        &json_global_sm_order_array(&params.global_sm_id[..sampled]),
    );
    json.field_bool("truncated", sampled < count);
    let mut route = JsonObject::new();
    route.field_str("flags", &format!("0x{:x}", params.gr_route_info.flags));
    route.field_str("route", &format!("0x{:x}", params.gr_route_info.route));
    json.field_raw("grRouteInfo", &route.finish());
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER, numSm={}, numTpc={}",
            params.num_sm, params.num_tpc
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gr_get_caps_v2(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv0080CtrlGrGetCapsV2Params>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GR_GET_CAPS_V2",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv0080CtrlGrGetCapsV2Params>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_raw("capsTbl", &json_u8_hex_array(&params.caps_tbl));
    json.field_bool("capsPopulated", params.b_caps_populated != 0);
    let mut route = JsonObject::new();
    route.field_str("flags", &format!("0x{:x}", params.gr_route_info.flags));
    route.field_str("route", &format!("0x{:x}", params.gr_route_info.route));
    json.field_raw("grRouteInfo", &route.finish());
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: "name=NV2080_CTRL_CMD_GR_GET_CAPS_V2".to_owned(),
        json: json.finish(),
    })
}

fn decode_cmd_gr_get_gpc_mask(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGrGetGpcMaskParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GR_GET_GPC_MASK",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGrGetGpcMaskParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_str("gpcMask", &format!("0x{:x}", params.gpc_mask));
    let mut route = JsonObject::new();
    route.field_str("flags", &format!("0x{:x}", params.gr_route_info.flags));
    route.field_str("route", &format!("0x{:x}", params.gr_route_info.route));
    json.field_raw("grRouteInfo", &route.finish());
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GR_GET_GPC_MASK, gpcMask=0x{:x}",
            params.gpc_mask
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gr_get_tpc_mask(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGrGetTpcMaskParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GR_GET_TPC_MASK",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGrGetTpcMaskParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_u64("gpcId", params.gpc_id as u64);
    json.field_str("tpcMask", &format!("0x{:x}", params.tpc_mask));
    let mut route = JsonObject::new();
    route.field_str("flags", &format!("0x{:x}", params.gr_route_info.flags));
    route.field_str("route", &format!("0x{:x}", params.gr_route_info.route));
    json.field_raw("grRouteInfo", &route.finish());
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GR_GET_TPC_MASK, gpcId={}, tpcMask=0x{:x}",
            params.gpc_id, params.tpc_mask
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gr_set_ctxsw_preemption_mode(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGrSetCtxswPreemptionModeParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGrSetCtxswPreemptionModeParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_str("flags", &format!("0x{:x}", params.flags));
    json.field_str("hChannel", &format!("0x{:x}", params.h_channel));
    json.field_u64("gfxpPreemptMode", params.gfxp_preempt_mode as u64);
    json.field_u64("cilpPreemptMode", params.cilp_preempt_mode as u64);
    let mut route = JsonObject::new();
    route.field_str("flags", &format!("0x{:x}", params.gr_route_info.flags));
    route.field_str("route", &format!("0x{:x}", params.gr_route_info.route));
    json.field_raw("grRouteInfo", &route.finish());
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: "name=NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE".to_owned(),
        json: json.finish(),
    })
}

fn decode_cmd_gr_get_ctx_buffer_size(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGrGetCtxBufferSizeParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGrGetCtxBufferSizeParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_str("hChannel", &format!("0x{:x}", params.h_channel));
    json.field_u64("totalBufferSize", params.total_buffer_size);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE, totalBufferSize={}",
            params.total_buffer_size
        ),
        json: json.finish(),
    })
}

fn decode_cmd_ce_get_all_caps(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlCeGetAllCapsParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_CE_GET_ALL_CAPS",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlCeGetAllCapsParams>(params_addr) }?;
    let mut entries = Vec::new();
    for (idx, caps) in params.caps_tbl.iter().enumerate() {
        let present = ((params.present >> idx) & 1) != 0;
        if present || caps[0] != 0 || caps[1] != 0 {
            entries.push((idx as u32, caps[0], caps[1], present));
        }
    }
    let mut json = JsonObject::new();
    json.field_str("presentMask", &format!("0x{:x}", params.present));
    json.field_raw("ceCaps", &json_ce_caps_array(&entries));
    json.field_u64(
        "presentCount",
        entries.iter().filter(|v| v.3).count() as u64,
    );
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_CE_GET_ALL_CAPS, presentMask=0x{:x}",
            params.present
        ),
        json: json.finish(),
    })
}

fn decode_cmd_nvlink_get_nvlink_status(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlNvlinkGetNvlinkStatusParamsPrefix>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlNvlinkGetNvlinkStatusParamsPrefix>(params_addr) }?;

    let mut json = JsonObject::new();
    json.field_str(
        "enabledLinkMask",
        &format!("0x{:x}", params.enabled_link_mask),
    );
    json.field_u64(
        "enabledLinksLenMasks",
        params.enabled_links.len_masks as u64,
    );
    json.field_str(
        "enabledLinksMask0",
        &format!("0x{:x}", params.enabled_links.masks[0]),
    );
    json.field_bool("sublinkStateInstant", params.b_sublink_state_inst != 0);
    json.field_bool("nvleModeEnabled", params.b_nvle_mode_enabled != 0);
    if params_size >= size_of::<u64>() {
        let enabled_nvlpw_mask_addr = params_addr + params_size - size_of::<u64>();
        if let Some(mask) = unsafe { read_pod::<u64>(enabled_nvlpw_mask_addr) } {
            json.field_str("enabledNvlpwMask", &format!("0x{:x}", mask));
        }
    }
    json.field_u64("paramsSize", params_size as u64);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS, enabledLinkMask=0x{:x}",
            params.enabled_link_mask
        ),
        json: json.finish(),
    })
}

fn decode_cmd_gsp_get_features(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGspGetFeaturesParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GSP_GET_FEATURES",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGspGetFeaturesParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_str("gspFeatures", &format!("0x{:x}", params.gsp_features));
    json.field_bool("valid", params.b_valid != 0);
    json.field_bool("defaultGspRmGpu", params.b_default_gsp_rm_gpu != 0);
    json.field_str("firmwareVersion", &read_c_string(&params.firmware_version));
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GSP_GET_FEATURES, valid={}",
            params.b_valid != 0
        ),
        json: json.finish(),
    })
}

fn decode_cmd_grmgr_get_gr_fs_info(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlGrmgrGetGrFsInfoParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlGrmgrGetGrFsInfoParams>(params_addr) }?;
    let count = min(params.num_queries as usize, params.queries.len());
    let sampled = min(count, MAX_CTRL_LIST_ITEMS);
    let mut json = JsonObject::new();
    json.field_u64("numQueries", params.num_queries as u64);
    json.field_raw(
        "queries",
        &json_grmgr_queries_array(&params.queries[..sampled]),
    );
    json.field_bool("truncated", sampled < count);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO, numQueries={}",
            params.num_queries
        ),
        json: json.finish(),
    })
}

fn decode_cmd_conf_compute_get_capabilities(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<NvConfComputeCtrlCmdSystemGetCapabilitiesParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES",
            expected,
            params_size,
        ));
    }
    let params =
        unsafe { read_pod::<NvConfComputeCtrlCmdSystemGetCapabilitiesParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_u64("cpuCapability", params.cpu_capability as u64);
    json.field_u64("gpusCapability", params.gpus_capability as u64);
    json.field_u64("environment", params.environment as u64);
    json.field_u64("ccFeature", params.cc_feature as u64);
    json.field_u64("devToolsMode", params.dev_tools_mode as u64);
    json.field_u64("multiGpuMode", params.multi_gpu_mode as u64);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: "name=NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES".to_owned(),
        json: json.finish(),
    })
}

fn decode_cmd_gpfifo_schedule(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nva06cCtrlGpfifoScheduleParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NVA06C_CTRL_CMD_GPFIFO_SCHEDULE",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nva06cCtrlGpfifoScheduleParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_bool("enable", params.b_enable != 0);
    json.field_bool("skipSubmit", params.b_skip_submit != 0);
    json.field_bool("skipEnable", params.b_skip_enable != 0);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: "name=NVA06C_CTRL_CMD_GPFIFO_SCHEDULE".to_owned(),
        json: json.finish(),
    })
}

fn decode_cmd_set_timeslice(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nva06cCtrlTimesliceParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NVA06C_CTRL_CMD_SET_TIMESLICE",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nva06cCtrlTimesliceParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_u64("timesliceUs", params.timeslice_us);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NVA06C_CTRL_CMD_SET_TIMESLICE, timesliceUs={}",
            params.timeslice_us
        ),
        json: json.finish(),
    })
}

fn decode_cmd_preempt(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nva06cCtrlPreemptParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NVA06C_CTRL_CMD_PREEMPT",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nva06cCtrlPreemptParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_bool("wait", params.b_wait != 0);
    json.field_bool("manualTimeout", params.b_manual_timeout != 0);
    json.field_u64("timeoutUs", params.timeout_us as u64);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NVA06C_CTRL_CMD_PREEMPT, timeoutUs={}",
            params.timeout_us
        ),
        json: json.finish(),
    })
}

fn decode_cmd_debug_set_exception_mask(
    params_addr: usize,
    params_size: usize,
) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv83deCtrlDebugSetExceptionMaskParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv83deCtrlDebugSetExceptionMaskParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_str("exceptionMask", &format!("0x{:x}", params.exception_mask));
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, mask=0x{:x}",
            params.exception_mask
        ),
        json: json.finish(),
    })
}

fn decode_cmd_perf_boost(params_addr: usize, params_size: usize) -> Option<KnownRmDecode> {
    let expected = size_of::<Nv2080CtrlPerfBoostParams>();
    if params_size < expected {
        return Some(known_size_mismatch(
            "NV2080_CTRL_CMD_PERF_BOOST",
            expected,
            params_size,
        ));
    }
    let params = unsafe { read_pod::<Nv2080CtrlPerfBoostParams>(params_addr) }?;
    let mut json = JsonObject::new();
    json.field_str("flags", &format!("0x{:x}", params.flags));
    json.field_u64("duration", params.duration as u64);
    json.field_str("status", "ok");
    Some(KnownRmDecode {
        legacy: format!(
            "name=NV2080_CTRL_CMD_PERF_BOOST, flags=0x{:x}, duration={}",
            params.flags, params.duration
        ),
        json: json.finish(),
    })
}

pub(super) fn outer_cmd_name(nr: u8) -> &'static str {
    match nr as u32 {
        NV_ESC_RM_ALLOC_MEMORY => "NV_ESC_RM_ALLOC_MEMORY",
        NV_ESC_RM_ALLOC_OBJECT => "NV_ESC_RM_ALLOC_OBJECT",
        NV_ESC_RM_FREE => "NV_ESC_RM_FREE",
        NV_ESC_RM_CONTROL => "NV_ESC_RM_CONTROL",
        NV_ESC_RM_ALLOC => "NV_ESC_RM_ALLOC",
        NV_ESC_RM_CONFIG_GET => "NV_ESC_RM_CONFIG_GET",
        NV_ESC_RM_CONFIG_SET => "NV_ESC_RM_CONFIG_SET",
        NV_ESC_RM_DUP_OBJECT => "NV_ESC_RM_DUP_OBJECT",
        NV_ESC_RM_SHARE => "NV_ESC_RM_SHARE",
        NV_ESC_RM_CONFIG_GET_EX => "NV_ESC_RM_CONFIG_GET_EX",
        NV_ESC_RM_CONFIG_SET_EX => "NV_ESC_RM_CONFIG_SET_EX",
        NV_ESC_RM_I2C_ACCESS => "NV_ESC_RM_I2C_ACCESS",
        NV_ESC_RM_IDLE_CHANNELS => "NV_ESC_RM_IDLE_CHANNELS",
        NV_ESC_RM_VID_HEAP_CONTROL => "NV_ESC_RM_VID_HEAP_CONTROL",
        NV_ESC_RM_ACCESS_REGISTRY => "NV_ESC_RM_ACCESS_REGISTRY",
        NV_ESC_RM_MAP_MEMORY => "NV_ESC_RM_MAP_MEMORY",
        NV_ESC_RM_UNMAP_MEMORY => "NV_ESC_RM_UNMAP_MEMORY",
        NV_ESC_RM_GET_EVENT_DATA => "NV_ESC_RM_GET_EVENT_DATA",
        NV_ESC_RM_ALLOC_CONTEXT_DMA2 => "NV_ESC_RM_ALLOC_CONTEXT_DMA2",
        NV_ESC_RM_ADD_VBLANK_CALLBACK => "NV_ESC_RM_ADD_VBLANK_CALLBACK",
        NV_ESC_RM_MAP_MEMORY_DMA => "NV_ESC_RM_MAP_MEMORY_DMA",
        NV_ESC_RM_UNMAP_MEMORY_DMA => "NV_ESC_RM_UNMAP_MEMORY_DMA",
        NV_ESC_RM_BIND_CONTEXT_DMA => "NV_ESC_RM_BIND_CONTEXT_DMA",
        NV_ESC_RM_EXPORT_OBJECT_TO_FD => "NV_ESC_RM_EXPORT_OBJECT_TO_FD",
        NV_ESC_RM_IMPORT_OBJECT_FROM_FD => "NV_ESC_RM_IMPORT_OBJECT_FROM_FD",
        NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO => "NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO",
        NV_ESC_RM_LOCKLESS_DIAGNOSTIC => "NV_ESC_RM_LOCKLESS_DIAGNOSTIC",
        NV_ESC_CARD_INFO => "NV_ESC_CARD_INFO",
        NV_ESC_REGISTER_FD => "NV_ESC_REGISTER_FD",
        NV_ESC_ALLOC_OS_EVENT => "NV_ESC_ALLOC_OS_EVENT",
        NV_ESC_FREE_OS_EVENT => "NV_ESC_FREE_OS_EVENT",
        NV_ESC_STATUS_CODE => "NV_ESC_STATUS_CODE",
        NV_ESC_CHECK_VERSION_STR => "NV_ESC_CHECK_VERSION_STR",
        NV_ESC_IOCTL_XFER_CMD => "NV_ESC_IOCTL_XFER_CMD",
        NV_ESC_ATTACH_GPUS_TO_FD => "NV_ESC_ATTACH_GPUS_TO_FD",
        NV_ESC_QUERY_DEVICE_INTR => "NV_ESC_QUERY_DEVICE_INTR",
        NV_ESC_SYS_PARAMS => "NV_ESC_SYS_PARAMS",
        NV_ESC_NUMA_INFO => "NV_ESC_NUMA_INFO",
        NV_ESC_SET_NUMA_STATUS => "NV_ESC_SET_NUMA_STATUS",
        NV_ESC_EXPORT_TO_DMABUF_FD => "NV_ESC_EXPORT_TO_DMABUF_FD",
        NV_ESC_WAIT_OPEN_COMPLETE => "NV_ESC_WAIT_OPEN_COMPLETE",
        _ => generated_nv_esc_cmd_name(nr as u32).unwrap_or("UNKNOWN"),
    }
}

static EXTRA_NV_ESC_CMD_NAMES: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();
static EXTRA_RM_CONTROL_CMD_NAMES: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();
static EXTRA_RM_INTERFACE_NAMES: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();

fn generated_nv_esc_cmd_name(nr: u32) -> Option<&'static str> {
    let map = EXTRA_NV_ESC_CMD_NAMES.get_or_init(load_extra_nv_esc_cmd_names);
    map.get(&nr).copied()
}

fn load_extra_nv_esc_cmd_names() -> HashMap<u32, &'static str> {
    let mut map = HashMap::new();
    for (nr, name) in generated_nvidia_ioctl_tables::GENERATED_NV_ESC_CMD_NAMES {
        map.entry(*nr).or_insert(*name);
    }
    map
}

fn generated_rm_control_cmd_name(cmd: u32) -> Option<&'static str> {
    let map = EXTRA_RM_CONTROL_CMD_NAMES.get_or_init(load_extra_rm_control_cmd_names);
    map.get(&cmd).copied()
}

fn generated_rm_interface_name(interface_id: u32) -> Option<&'static str> {
    let map = EXTRA_RM_INTERFACE_NAMES.get_or_init(load_extra_rm_interface_names);
    map.get(&interface_id).copied()
}

fn load_extra_rm_control_cmd_names() -> HashMap<u32, &'static str> {
    let mut map = HashMap::new();
    for (cmd, name) in generated_nvidia_ioctl_tables::GENERATED_RM_CONTROL_CMD_NAMES {
        map.entry(*cmd).or_insert(*name);
    }
    map
}

fn load_extra_rm_interface_names() -> HashMap<u32, &'static str> {
    let mut map = HashMap::new();
    for (interface_id, name) in generated_nvidia_ioctl_tables::GENERATED_RM_INTERFACE_NAMES {
        map.entry(*interface_id).or_insert(*name);
    }
    map
}

fn rm_control_cmd_name(cmd: u32) -> String {
    match cmd {
        NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION => {
            "NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION".to_owned()
        }
        NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS => {
            "NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS".to_owned()
        }
        NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX => {
            "NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX".to_owned()
        }
        NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE => {
            "NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE".to_owned()
        }
        NV0000_CTRL_CMD_OS_UNIX_GET_CONTROL_FILE_DESCRIPTOR => {
            "NV0000_CTRL_CMD_OS_UNIX_GET_CONTROL_FILE_DESCRIPTOR".to_owned()
        }
        NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY => {
            "NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY".to_owned()
        }
        NV0000_CTRL_CMD_SYSTEM_GET_FEATURES => "NV0000_CTRL_CMD_SYSTEM_GET_FEATURES".to_owned(),
        NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE => "NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE".to_owned(),
        NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS => "NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS".to_owned(),
        NV0000_CTRL_CMD_GPU_GET_ID_INFO => "NV0000_CTRL_CMD_GPU_GET_ID_INFO".to_owned(),
        NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 => "NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2".to_owned(),
        NV0000_CTRL_CMD_GPU_GET_PROBED_IDS => "NV0000_CTRL_CMD_GPU_GET_PROBED_IDS".to_owned(),
        NV0000_CTRL_CMD_GPU_ATTACH_IDS => "NV0000_CTRL_CMD_GPU_ATTACH_IDS".to_owned(),
        NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS => {
            "NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS".to_owned()
        }
        NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO => {
            "NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO".to_owned()
        }
        NV0080_CTRL_CMD_HOST_GET_CAPS_V2 => "NV0080_CTRL_CMD_HOST_GET_CAPS_V2".to_owned(),
        NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES => {
            "NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES".to_owned()
        }
        NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2 => "NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2".to_owned(),
        NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE => {
            "NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE".to_owned()
        }
        NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST => "NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST".to_owned(),
        NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL => {
            "NV0080_CTRL_CMD_PERF_CUDA_LIMIT_SET_CONTROL".to_owned()
        }
        NV0080_CTRL_CMD_FB_GET_CAPS_V2 => "NV0080_CTRL_CMD_FB_GET_CAPS_V2".to_owned(),
        NV906F_CTRL_GET_CLASS_ENGINEID => "NV906F_CTRL_GET_CLASS_ENGINEID".to_owned(),
        NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN => {
            "NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN".to_owned()
        }
        NV2080_CTRL_CMD_GPU_GET_INFO_V2 => "NV2080_CTRL_CMD_GPU_GET_INFO_V2".to_owned(),
        NV2080_CTRL_CMD_GPU_GET_NAME_STRING => "NV2080_CTRL_CMD_GPU_GET_NAME_STRING".to_owned(),
        NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING => {
            "NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING".to_owned()
        }
        NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO => {
            "NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO".to_owned()
        }
        NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS => "NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS".to_owned(),
        NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES => {
            "NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES".to_owned()
        }
        NV2080_CTRL_CMD_GPU_GET_GID_INFO => "NV2080_CTRL_CMD_GPU_GET_GID_INFO".to_owned(),
        NV2080_CTRL_CMD_GPU_GET_ENGINES_V2 => "NV2080_CTRL_CMD_GPU_GET_ENGINES_V2".to_owned(),
        NV2080_CTRL_CMD_GR_GET_INFO => "NV2080_CTRL_CMD_GR_GET_INFO".to_owned(),
        NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER => {
            "NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER".to_owned()
        }
        NV2080_CTRL_CMD_GR_GET_CAPS_V2 => "NV2080_CTRL_CMD_GR_GET_CAPS_V2".to_owned(),
        NV2080_CTRL_CMD_GR_GET_GPC_MASK => "NV2080_CTRL_CMD_GR_GET_GPC_MASK".to_owned(),
        NV2080_CTRL_CMD_GR_GET_TPC_MASK => "NV2080_CTRL_CMD_GR_GET_TPC_MASK".to_owned(),
        NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE => {
            "NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE".to_owned()
        }
        NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE => {
            "NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE".to_owned()
        }
        NV2080_CTRL_CMD_FB_GET_INFO_V2 => "NV2080_CTRL_CMD_FB_GET_INFO_V2".to_owned(),
        NV2080_CTRL_CMD_MC_GET_ARCH_INFO => "NV2080_CTRL_CMD_MC_GET_ARCH_INFO".to_owned(),
        NV2080_CTRL_CMD_BUS_GET_PCI_INFO => "NV2080_CTRL_CMD_BUS_GET_PCI_INFO".to_owned(),
        NV2080_CTRL_CMD_BUS_GET_INFO_V2 => "NV2080_CTRL_CMD_BUS_GET_INFO_V2".to_owned(),
        NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO => "NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO".to_owned(),
        NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS => {
            "NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS".to_owned()
        }
        NV2080_CTRL_CMD_BUS_GET_C2C_INFO => "NV2080_CTRL_CMD_BUS_GET_C2C_INFO".to_owned(),
        NV2080_CTRL_CMD_PERF_BOOST => "NV2080_CTRL_CMD_PERF_BOOST".to_owned(),
        NV2080_CTRL_CMD_CE_GET_ALL_CAPS => "NV2080_CTRL_CMD_CE_GET_ALL_CAPS".to_owned(),
        NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS => {
            "NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS".to_owned()
        }
        NV2080_CTRL_CMD_GSP_GET_FEATURES => "NV2080_CTRL_CMD_GSP_GET_FEATURES".to_owned(),
        NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO => "NV2080_CTRL_CMD_GRMGR_GET_GR_FS_INFO".to_owned(),
        NVA06C_CTRL_CMD_GPFIFO_SCHEDULE => "NVA06C_CTRL_CMD_GPFIFO_SCHEDULE".to_owned(),
        NVA06C_CTRL_CMD_SET_TIMESLICE => "NVA06C_CTRL_CMD_SET_TIMESLICE".to_owned(),
        NVA06C_CTRL_CMD_PREEMPT => "NVA06C_CTRL_CMD_PREEMPT".to_owned(),
        NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK => {
            "NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK".to_owned()
        }
        NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES => {
            "NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES".to_owned()
        }
        _ => generated_rm_control_cmd_name(cmd)
            .map(str::to_owned)
            .unwrap_or_else(|| rm_control_cmd_name_fallback(cmd)),
    }
}

fn rm_control_cmd_name_fallback(cmd: u32) -> String {
    if let Some((family, msg_id)) = rm_control_legacy_family_and_msg_id(cmd) {
        return format!("NV2080_CTRL_CMD_{family}_0x{msg_id:02x}");
    }

    if let Some(interface_name) = rm_control_interface_name(cmd) {
        let msg_id = (cmd & 0xff) as u8;
        return format!("NV2080_CTRL_CMD_{interface_name}_0x{msg_id:02x}");
    }

    let interface_id = cmd >> 8;
    let msg_id = (cmd & 0xff) as u8;
    if let Some(interface_name) = generated_rm_interface_name(interface_id) {
        return format!("{interface_name}_CMD_0x{msg_id:02x}");
    }

    "UNKNOWN".to_owned()
}

fn rm_control_params_type_name(cmd_name: &str) -> Option<String> {
    if cmd_name == "UNKNOWN" {
        return None;
    }
    let (prefix, suffix) = cmd_name.split_once("_CMD_")?;
    if suffix.is_empty() {
        return None;
    }
    Some(format!("{prefix}_{suffix}_PARAMS"))
}

fn rm_control_interface_name(cmd: u32) -> Option<&'static str> {
    if (cmd >> 16) != 0x2080 {
        return None;
    }
    nv2080_interface_name(((cmd >> 8) & 0xff) as u8)
}

fn rm_control_legacy_family_and_msg_id(cmd: u32) -> Option<(&'static str, u8)> {
    if (cmd >> 16) != 0x2080 {
        return None;
    }
    let interface = ((cmd >> 8) & 0xff) as u8;
    let msg_id = (cmd & 0xff) as u8;
    let family = match interface {
        0x81 => "GPU_LEGACY_NON_PRIVILEGED",
        0x82 => "FUSE_LEGACY_NON_PRIVILEGED",
        0x85 => "THERMAL_LEGACY_NON_PRIVILEGED",
        0x90 => "CLK_LEGACY_NON_PRIVILEGED",
        0xa0 => "PERF_LEGACY_NON_PRIVILEGED",
        0xa3 => "GPIO_LEGACY_NON_PRIVILEGED",
        0xa6 => "PMGR_LEGACY_NON_PRIVILEGED",
        0xa7 => "POWER_LEGACY_NON_PRIVILEGED",
        0xa8 => "LPWR_LEGACY_NON_PRIVILEGED",
        0xb2 => "VOLT_LEGACY_NON_PRIVILEGED",
        0xb4 => "ECC_NON_PRIVILEGED",
        0xb7 => "NNE_LEGACY_NON_PRIVILEGED",
        0xc5 => "THERMAL_LEGACY_PRIVILEGED",
        0xd0 => "CLK_LEGACY_PRIVILEGED",
        0xe0 => "PERF_LEGACY_PRIVILEGED",
        0xe6 => "PMGR_LEGACY_PRIVILEGED",
        0xe8 => "LPWR_LEGACY_PRIVILEGED",
        0xf2 => "VOLT_LEGACY_PRIVILEGED",
        _ => return None,
    };
    Some((family, msg_id))
}

fn nv2080_interface_name(interface: u8) -> Option<&'static str> {
    let name = match interface {
        0x00 => "RESERVED",
        0x01 => "GPU",
        0x81 => "GPU_LEGACY_NON_PRIVILEGED",
        0x02 => "FUSE",
        0x82 => "FUSE_LEGACY_NON_PRIVILEGED",
        0x03 => "EVENT",
        0x04 => "TIMER",
        0x05 => "THERMAL",
        0xc5 => "THERMAL_LEGACY_PRIVILEGED",
        0x85 => "THERMAL_LEGACY_NON_PRIVILEGED",
        0x06 => "I2C",
        0x07 => "EXTI2C",
        0x08 => "BIOS",
        0x09 => "CIPHER",
        0x0a => "INTERNAL",
        0xd0 => "CLK_LEGACY_PRIVILEGED",
        0x90 => "CLK_LEGACY_NON_PRIVILEGED",
        0x10 => "CLK",
        0x11 => "FIFO",
        0x12 => "GR",
        0x13 => "FB",
        0x17 => "MC",
        0x18 => "BUS",
        0xe0 => "PERF_LEGACY_PRIVILEGED",
        0xa0 => "PERF_LEGACY_NON_PRIVILEGED",
        0x20 => "PERF",
        0x21 => "NVIF",
        0x22 => "RC",
        0x23 => "GPIO",
        0xa3 => "GPIO_LEGACY_NON_PRIVILEGED",
        0x24 => "NVD",
        0x25 => "DMA",
        0x26 => "PMGR",
        0xe6 => "PMGR_LEGACY_PRIVILEGED",
        0xa6 => "PMGR_LEGACY_NON_PRIVILEGED",
        0x27 => "POWER",
        0xa7 => "POWER_LEGACY_NON_PRIVILEGED",
        0x28 => "LPWR",
        0xa8 => "LPWR_LEGACY_NON_PRIVILEGED",
        0xe8 => "LPWR_LEGACY_PRIVILEGED",
        0x29 => "ACR",
        0x2a => "CE",
        0x2b => "SPI",
        0x30 => "NVLINK",
        0x31 => "FLCN",
        0x32 => "VOLT",
        0xf2 => "VOLT_LEGACY_PRIVILEGED",
        0xb2 => "VOLT_LEGACY_NON_PRIVILEGED",
        0x33 => "FAS",
        0x34 => "ECC",
        0xb4 => "ECC_NON_PRIVILEGED",
        0x35 => "FLA",
        0x36 => "GSP",
        0x37 => "NNE",
        0xb7 => "NNE_LEGACY_NON_PRIVILEGED",
        0x38 => "GRMGR",
        0x39 => "UCODE_FUZZER",
        0x3a => "DMABUF",
        0x3b => "BIF",
        0x3d => "OS_UNIX",
        0x3e => "OS_MACOS",
        0x3f => "OS_WINDOWS",
        _ => return None,
    };
    Some(name)
}

fn rm_vid_heap_function_name(function: u32) -> &'static str {
    match function {
        2 => "NVOS32_FUNCTION_ALLOC_SIZE",
        3 => "NVOS32_FUNCTION_FREE",
        5 => "NVOS32_FUNCTION_INFO",
        6 => "NVOS32_FUNCTION_ALLOC_TILED_PITCH_HEIGHT",
        14 => "NVOS32_FUNCTION_ALLOC_SIZE_RANGE",
        15 => "NVOS32_FUNCTION_REACQUIRE_COMPR",
        16 => "NVOS32_FUNCTION_RELEASE_COMPR",
        18 => "NVOS32_FUNCTION_GET_MEM_ALIGNMENT",
        19 => "NVOS32_FUNCTION_HW_ALLOC",
        20 => "NVOS32_FUNCTION_HW_FREE",
        27 => "NVOS32_FUNCTION_ALLOC_OS_DESCRIPTOR",
        _ => "UNKNOWN",
    }
}

fn virtualization_mode_name(mode: u32) -> &'static str {
    match mode {
        0 => "NONE",
        1 => "NMOS",
        2 => "VGX",
        3 => "HOST/HOST_VGPU",
        4 => "HOST_VSGA",
        _ => "UNKNOWN",
    }
}

fn fabric_status_name(value: u32) -> &'static str {
    match value {
        1 => "SKIP",
        2 => "UNINITIALIZED",
        3 => "IN_PROGRESS",
        4 => "INITIALIZED",
        _ => "UNKNOWN",
    }
}

fn simulation_info_type_name(value: u32) -> &'static str {
    match value {
        0 => "NONE",
        1 => "MODS_AMODEL",
        2 => "LIVE_AMODEL",
        3 => "FMODEL",
        4 => "RTL",
        5 => "EMU",
        6 => "EMU_LOW_POWER",
        7 => "DFPGA",
        8 => "DFPGA_RTL",
        9 => "DFPGA_FMODEL",
        0xffff_ffff => "UNKNOWN_FLAG",
        _ => "UNKNOWN",
    }
}

fn compute_mode_rules_name(value: u32) -> &'static str {
    match value {
        0 => "NONE",
        1 => "EXCLUSIVE_COMPUTE",
        2 => "COMPUTE_PROHIBITED",
        3 => "EXCLUSIVE_COMPUTE_PROCESS",
        _ => "UNKNOWN",
    }
}

fn c2c_remote_type_name(value: u32) -> &'static str {
    match value {
        0 => "NONE",
        1 => "CPU",
        2 => "GPU",
        _ => "UNKNOWN",
    }
}

fn grmgr_query_type_name(value: u16) -> &'static str {
    match value as u32 {
        1 => "GPC_COUNT",
        2 => "CHIPLET_GPC_MAP",
        3 => "TPC_MASK",
        4 => "PPC_MASK",
        5 => "PARTITION_CHIPLET_GPC_MAP",
        6 => "CHIPLET_SYSPIPE_MASK",
        7 => "PARTITION_CHIPLET_SYSPIPE_IDS",
        8 => "PROFILER_MON_GPC_MASK",
        9 => "PARTITION_SYSPIPE_ID",
        10 => "ROP_MASK",
        11 => "CHIPLET_GRAPHICS_SYSPIPE_MASK",
        12 => "GFX_CAPABLE_GPC_MASK",
        _ => "UNKNOWN",
    }
}

fn valid_gpu_ids(all_ids: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    for gpu_id in all_ids {
        if *gpu_id == 0xffff_ffff {
            break;
        }
        out.push(*gpu_id);
    }
    out
}

fn read_remote_string(ptr: u64, length: usize, max_blob: usize) -> Option<String> {
    if ptr == 0 || length == 0 {
        return None;
    }
    let read_len = min(length, max_blob.max(32));
    let bytes = unsafe { read_bytes(ptr as usize, read_len) }?;
    let nul = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..nul]).into_owned())
}

fn json_u8_array(values: &[u8]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&value.to_string());
    }
    out.push(']');
    out
}

fn json_u8_hex_array(values: &[u8]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&format!("0x{:02x}", value));
        out.push('"');
    }
    out.push(']');
    out
}

fn json_u32_hex_array(values: &[u32]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&format!("0x{:x}", value));
        out.push('"');
    }
    out.push(']');
    out
}

fn json_u32_matrix<const R: usize, const C: usize>(
    values: &[[u32; C]; R],
    rows: usize,
    cols: usize,
) -> String {
    let row_count = min(rows, R);
    let col_count = min(cols, C);
    let mut out = String::from("[");
    for row_idx in 0..row_count {
        if row_idx > 0 {
            out.push(',');
        }
        out.push('[');
        for col_idx in 0..col_count {
            if col_idx > 0 {
                out.push(',');
            }
            out.push_str(&values[row_idx][col_idx].to_string());
        }
        out.push(']');
    }
    out.push(']');
    out
}

fn json_share_policy(policy: &RsSharePolicy) -> String {
    let mut obj = JsonObject::new();
    obj.field_str("target", &format!("0x{:x}", policy.target));
    obj.field_str(
        "accessMask",
        &format!("0x{:x}", policy.access_mask.limbs[0]),
    );
    obj.field_u64("type", policy.policy_type as u64);
    obj.field_u64("action", policy.action as u64);
    obj.finish()
}

fn json_active_device_array(values: &[Nv0000CtrlGpuActiveDevice]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let mut obj = JsonObject::new();
        obj.field_u64("gpuId", value.gpu_id as u64);
        obj.field_u64("gpuInstanceId", value.gpu_instance_id as u64);
        obj.field_u64("computeInstanceId", value.compute_instance_id as u64);
        out.push_str(&obj.finish());
    }
    out.push(']');
    out
}

fn json_sync_gpu_boost_group_array(values: &[Nv0000SyncGpuBoostGroupConfig]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let gpu_count = min(value.gpu_count as usize, value.gpu_ids.len());
        let mut obj = JsonObject::new();
        obj.field_u64("gpuCount", value.gpu_count as u64);
        obj.field_raw("gpuIds", &json_u32_array(&value.gpu_ids[..gpu_count]));
        obj.field_str("boostGroupId", &format!("0x{:x}", value.boost_group_id));
        obj.field_bool("bridgeless", value.b_bridgeless != 0);
        out.push_str(&obj.finish());
    }
    out.push(']');
    out
}

fn json_xxx_info_array(values: &[NvxxxxCtrlXxxInfo]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let mut obj = JsonObject::new();
        obj.field_str("index", &format!("0x{:x}", value.index));
        obj.field_str("data", &format!("0x{:x}", value.data));
        out.push_str(&obj.finish());
    }
    out.push(']');
    out
}

fn json_global_sm_order_array(values: &[Nv2080CtrlGrGlobalSmId]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let mut obj = JsonObject::new();
        obj.field_u64("gpcId", value.gpc_id as u64);
        obj.field_u64("localTpcId", value.local_tpc_id as u64);
        obj.field_u64("localSmId", value.local_sm_id as u64);
        obj.field_u64("globalTpcId", value.global_tpc_id as u64);
        obj.field_u64("virtualGpcId", value.virtual_gpc_id as u64);
        obj.field_u64("migratableTpcId", value.migratable_tpc_id as u64);
        obj.field_u64("uGpuId", value.ugpu_id as u64);
        obj.field_u64("physicalCpcId", value.physical_cpc_id as u64);
        obj.field_u64("virtualTpcId", value.virtual_tpc_id as u64);
        out.push_str(&obj.finish());
    }
    out.push(']');
    out
}

fn json_ecc_unit_sample_array(values: &[(u32, &Nv2080CtrlGpuQueryEccUnitStatus)]) -> String {
    let mut out = String::from("[");
    for (idx, (unit_idx, unit)) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let mut obj = JsonObject::new();
        obj.field_u64("unit", *unit_idx as u64);
        obj.field_bool("enabled", unit.enabled != 0);
        obj.field_bool("supported", unit.supported != 0);
        obj.field_bool("scrubComplete", unit.scrub_complete != 0);
        obj.field_u64("dbe", unit.dbe.count);
        obj.field_u64("dbeNonResettable", unit.dbe_non_resettable.count);
        obj.field_u64("sbe", unit.sbe.count);
        obj.field_u64("sbeNonResettable", unit.sbe_non_resettable.count);
        out.push_str(&obj.finish());
    }
    out.push(']');
    out
}

fn json_ce_caps_array(values: &[(u32, u8, u8, bool)]) -> String {
    let mut out = String::from("[");
    for (idx, (ce_idx, caps0, caps1, present)) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let mut obj = JsonObject::new();
        obj.field_u64("ce", *ce_idx as u64);
        obj.field_bool("present", *present);
        obj.field_str("caps0", &format!("0x{:02x}", caps0));
        obj.field_str("caps1", &format!("0x{:02x}", caps1));
        out.push_str(&obj.finish());
    }
    out.push(']');
    out
}

fn json_grmgr_queries_array(values: &[Nv2080CtrlGrmgrGrFsInfoQueryParams]) -> String {
    let mut out = String::from("[");
    for (idx, query) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let mut obj = JsonObject::new();
        obj.field_u64("queryType", query.query_type as u64);
        obj.field_str("queryName", grmgr_query_type_name(query.query_type));
        obj.field_i64("queryStatus", query.status as i64);
        obj.field_raw("queryData", &json_u32_hex_array(&query.query_data_words));
        out.push_str(&obj.finish());
    }
    out.push(']');
    out
}

fn json_pci_bar_info_array(values: &[Nv2080CtrlBusPciBarInfo]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let mut obj = JsonObject::new();
        obj.field_str("flags", &format!("0x{:x}", value.flags));
        obj.field_u64("barSizeMb", value.bar_size as u64);
        obj.field_u64("barSizeBytes", value.bar_size_bytes);
        obj.field_str("barOffset", &format!("0x{:x}", value.bar_offset));
        out.push_str(&obj.finish());
    }
    out.push(']');
    out
}

fn json_atomic_op_array(values: &[Nv2080CtrlBusPcieGpuAtomicOpInfo]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let mut obj = JsonObject::new();
        obj.field_str("op", pcie_atomic_op_name(idx));
        obj.field_bool("supported", value.b_supported != 0);
        obj.field_str("attributes", &format!("0x{:x}", value.attributes));
        out.push_str(&obj.finish());
    }
    out.push(']');
    out
}

fn pcie_atomic_op_name(index: usize) -> &'static str {
    match index {
        0 => "IADD",
        1 => "IMIN",
        2 => "IMAX",
        3 => "INC",
        4 => "DEC",
        5 => "IAND",
        6 => "IOR",
        7 => "IXOR",
        8 => "EXCH",
        9 => "CAS",
        10 => "FADD",
        11 => "FMIN",
        12 => "FMAX",
        _ => "UNKNOWN",
    }
}

fn write_rm_alloc_class(root: &mut JsonObject, class_id: i32) {
    root.field_str("hClass", &format!("0x{:x}", class_id as u32));
    let class_name = rm_alloc_class_name(class_id)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("UNKNOWN(0x{:x})", class_id as u32));
    root.field_str("hClassName", &class_name);
}

fn rm_alloc_class_name(class_id: i32) -> Option<&'static str> {
    match class_id {
        NV01_ROOT => Some("NV01_ROOT"),
        NV01_ROOT_NON_PRIV => Some("NV01_ROOT_NON_PRIV"),
        NV01_ROOT_CLIENT => Some("NV01_ROOT_CLIENT"),
        0x0000_003e => Some("NV01_MEMORY_SYSTEM"),
        0x0000_0040 => Some("NV01_MEMORY_LOCAL_USER"),
        0x0000_0071 => Some("NV01_MEMORY_SYSTEM_OS_DESCRIPTOR"),
        0x0000_0079 => Some("NV01_EVENT_OS_EVENT"),
        0x0000_0080 => Some("NV01_DEVICE_0"),
        0x0000_00de => Some("RM_USER_SHARED_DATA"),
        0x0000_2080 => Some("NV20_SUBDEVICE_0"),
        0x0000_2081 => Some("NV2081_BINAPI"),
        0x0000_50a0 => Some("NV50_MEMORY_VIRTUAL"),
        0x0000_83de => Some("GT200_DEBUGGER"),
        0x0000_9067 => Some("FERMI_CONTEXT_SHARE_A"),
        0x0000_90f1 => Some("FERMI_VASPACE_A"),
        0x0000_a06c => Some("KEPLER_CHANNEL_GROUP_A"),
        0x0000_c461 => Some("TURING_USERMODE_A"),
        0x0000_c56f => Some("AMPERE_CHANNEL_GPFIFO_A"),
        0x0000_c7b5 => Some("AMPERE_DMA_COPY_B"),
        0x0000_c7c0 => Some("AMPERE_COMPUTE_B"),
        0x0000_cb33 => Some("NV_CONFIDENTIAL_COMPUTE"),
        _ => None,
    }
}

fn nvos02_flags_physicality_name(value: u32) -> &'static str {
    match value {
        0x0 => "CONTIGUOUS",
        0x1 => "NONCONTIGUOUS",
        _ => "UNKNOWN",
    }
}

fn nvos02_flags_location_name(value: u32) -> &'static str {
    match value {
        0x0 => "PCI",
        0x2 => "VIDMEM",
        _ => "UNKNOWN",
    }
}

fn nvos02_flags_coherency_name(value: u32) -> &'static str {
    match value {
        0x0 => "UNCACHED",
        0x1 => "CACHED",
        0x2 => "WRITE_COMBINE",
        0x3 => "WRITE_THROUGH",
        0x4 => "WRITE_PROTECT",
        0x5 => "WRITE_BACK",
        _ => "UNKNOWN",
    }
}

fn nvos02_flags_alloc_name(value: u32) -> &'static str {
    match value {
        0x0 => "DEFAULT",
        0x1 => "NONE",
        _ => "UNKNOWN",
    }
}

fn nvos02_flags_mapping_name(value: u32) -> &'static str {
    match value {
        0x0 => "DEFAULT",
        0x1 => "NO_MAP",
        0x2 => "NEVER_MAP",
        _ => "UNKNOWN",
    }
}

fn addr_space_type_name(value: u32) -> &'static str {
    match value {
        NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_INVALID => "INVALID",
        NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_SYSMEM => "SYSMEM",
        NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_VIDMEM => "VIDMEM",
        NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_REGMEM => "REGMEM",
        NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_FABRIC => "FABRIC",
        NV0000_CTRL_CLIENT_GET_ADDR_SPACE_TYPE_FABRIC_MC => "FABRIC_MC",
        _ => "UNKNOWN",
    }
}

fn read_c_string(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

fn read_utf16le_c_string(bytes: &[u8]) -> String {
    let mut units = Vec::new();
    for pair in bytes.chunks_exact(2) {
        let value = u16::from_le_bytes([pair[0], pair[1]]);
        if value == 0 {
            break;
        }
        units.push(value);
    }
    String::from_utf16_lossy(&units)
}

fn json_u32_array(values: &[u32]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&value.to_string());
    }
    out.push(']');
    out
}

fn json_u64_hex_array(values: &[u64]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&format!("0x{:x}", value));
        out.push('"');
    }
    out.push(']');
    out
}

fn json_card_info_array(values: &[NvIoctlCardInfo]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&json_card_info(idx, value));
    }
    out.push(']');
    out
}

fn json_card_info(idx: usize, entry: &NvIoctlCardInfo) -> String {
    let mut obj = JsonObject::new();
    obj.field_u64("index", idx as u64);
    obj.field_bool("valid", entry.valid != 0);
    obj.field_u64("domain", entry.pci_info.domain as u64);
    obj.field_u64("bus", entry.pci_info.bus as u64);
    obj.field_u64("slot", entry.pci_info.slot as u64);
    obj.field_u64("function", entry.pci_info.function as u64);
    obj.field_u64("vendorId", entry.pci_info.vendor_id as u64);
    obj.field_u64("deviceId", entry.pci_info.device_id as u64);
    obj.field_str(
        "bdf",
        &format!(
            "{:04x}:{:02x}:{:02x}.{}",
            entry.pci_info.domain, entry.pci_info.bus, entry.pci_info.slot, entry.pci_info.function
        ),
    );
    obj.field_u64("gpuId", entry.gpu_id as u64);
    obj.field_u64("interruptLine", entry.interrupt_line as u64);
    obj.field_str("regAddress", &format!("0x{:x}", entry.reg_address));
    obj.field_u64("regSize", entry.reg_size);
    obj.field_str("fbAddress", &format!("0x{:x}", entry.fb_address));
    obj.field_u64("fbSize", entry.fb_size);
    obj.field_u64("minorNumber", entry.minor_number as u64);
    obj.field_str("devName", &read_c_string(&entry.dev_name));
    obj.finish()
}

#[cfg(test)]
mod tests {
    use super::{
        c2c_remote_type_name, deref_user_pointer, looks_like_user_pointer, nvos02_flags_alloc_name,
        rm_control_cmd_name,
    };
    use std::mem::size_of;

    #[test]
    fn generated_ctrl_names_fill_unknown_gaps() {
        // From ctrl0000system.h:
        // #define NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION_V2 (0x13eU)
        assert_eq!(
            rm_control_cmd_name(0x13e),
            "NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION_V2"
        );
        // From ctrl2080gpu.h:
        // #define NV2080_CTRL_CMD_GPU_GET_ENGINE_PARTNERLIST (0x20800147U)
        assert_eq!(
            rm_control_cmd_name(0x20800147),
            "NV2080_CTRL_CMD_GPU_GET_ENGINE_PARTNERLIST"
        );
        // From ctrl2080i2c.h (outside previous small include subset):
        // #define NV2080_CTRL_CMD_I2C_READ_BUFFER (0x20800601U)
        assert_eq!(
            rm_control_cmd_name(0x20800601),
            "NV2080_CTRL_CMD_I2C_READ_BUFFER"
        );
        // From g_finn_rm_api.h (interface-level fallback):
        // #define FINN_NV2081_BINAPI_INTERFACE_ID (0x208101U)
        assert_eq!(rm_control_cmd_name(0x20810108), "NV2081_BINAPI_CMD_0x08");
    }

    #[test]
    fn legacy_ctrl_names_have_fallback_names() {
        assert_eq!(
            rm_control_cmd_name(0x20809009),
            "NV2080_CTRL_CMD_CLK_LEGACY_NON_PRIVILEGED_0x09"
        );
        assert_eq!(
            rm_control_cmd_name(0x2080a084),
            "NV2080_CTRL_CMD_PERF_LEGACY_NON_PRIVILEGED_0x84"
        );
    }

    #[test]
    fn remove_known_unknown_labels_from_common_paths() {
        assert_eq!(c2c_remote_type_name(0), "NONE");
        assert_eq!(nvos02_flags_alloc_name(0), "DEFAULT");
    }

    #[test]
    fn deref_pointer_expands_nested_string() {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Inner {
            tag: u64,
            str_ptr: u64,
        }

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Root {
            inner_ptr: u64,
            flags: u64,
        }

        let text = b"alloc-parms\0";
        let inner = Inner {
            tag: 7,
            str_ptr: text.as_ptr() as u64,
        };
        let root = Root {
            inner_ptr: (&inner as *const Inner) as u64,
            flags: 0x55aa,
        };
        let prefetched = unsafe {
            std::slice::from_raw_parts((&root as *const Root).cast::<u8>(), size_of::<Root>())
        };

        let mut visited = Vec::new();
        let mut budget = 512;
        let json = deref_user_pointer(
            (&root as *const Root) as u64,
            size_of::<Root>(),
            0,
            3,
            64,
            prefetched,
            &mut visited,
            &mut budget,
        );

        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"ptrFields\""));
        assert!(json.contains("alloc-parms"));
    }

    #[test]
    fn deref_pointer_detects_cycle() {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct LoopNode {
            next: u64,
        }

        let mut node = LoopNode { next: 0 };
        node.next = (&node as *const LoopNode) as u64;
        let prefetched = unsafe {
            std::slice::from_raw_parts((&node as *const LoopNode).cast::<u8>(), size_of::<LoopNode>())
        };

        let mut visited = Vec::new();
        let mut budget = 128;
        let json = deref_user_pointer(
            (&node as *const LoopNode) as u64,
            size_of::<LoopNode>(),
            0,
            4,
            32,
            prefetched,
            &mut visited,
            &mut budget,
        );

        assert!(json.contains("cycle_detected"));
    }

    #[test]
    fn pointer_heuristic_filters_kernel_space() {
        assert!(looks_like_user_pointer(0x7fff_0000_1000));
        assert!(!looks_like_user_pointer(0xffff_8888_0000_0000));
        assert!(!looks_like_user_pointer(0x123));
    }
}
