#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define NV_IOCTL_MAGIC 'F'
#define NV_ESC_RM_CONTROL 0x2a

struct nested_payload {
    uint32_t value;
    const char *name;
};

struct demo_payload {
    struct nested_payload *nested;
    const char *message;
    uint32_t payload_len;
    const uint8_t *payload;
};

struct nvos54_parameters {
    uint32_t h_client;
    uint32_t h_object;
    uint32_t cmd;
    uint32_t flags;
    uint64_t params;
    uint32_t params_size;
    int32_t status;
};

int main(void) {
    int fd = open("/dev/nvidiactl", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/nvidiactl");
        return 1;
    }

    static const uint8_t blob[] = {0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44};
    struct nested_payload nested = {
        .value = 0x11223344,
        .name = "nested-string",
    };
    struct demo_payload params = {
        .nested = &nested,
        .message = "outer-message",
        .payload_len = sizeof(blob),
        .payload = blob,
    };
    struct nvos54_parameters os54 = {
        .h_client = 1,
        .h_object = 2,
        .cmd = 0x00ffee11, /* intentionally unknown; forces preview + deref path */
        .flags = 0,
        .params = (uint64_t)(uintptr_t)&params,
        .params_size = sizeof(params),
        .status = 0,
    };

    unsigned long rm_control_ioctl =
        _IOC(_IOC_READ | _IOC_WRITE, NV_IOCTL_MAGIC, NV_ESC_RM_CONTROL, sizeof(os54));
    int rc = ioctl(fd, rm_control_ioctl, &os54);
    printf("ioctl rc=%d errno=%d (%s)\n", rc, errno, strerror(errno));

    close(fd);
    return 0;
}
