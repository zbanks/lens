#include <libusb.h>
#include "log.h"
#include "base.h"

#define VENDOR_ID           0xFFFF
#define PRODUCT_ID          0xFFFC

//#define VENDOR_READ         0xC0
//#define VENDOR_WRITE        0x40

#define ACCEL_ADDR          0x1D

#define CTRL_READ_REG_8     0x20
#define CTRL_WRITE_REG_8    0x21
#define CTRL_READ_REG_16    0x22
#define CTRL_SET_LED        0x23
#define CTRL_SET_RELAYS     0x24
#define CTRL_SET_FAULT      0x25 // Wvalue   state that relays should go into, same as SET_RELAYS
#define CTRL_HEARTBEAT      0x26 // Wvalue   time in ticks

#define TIMEOUT             1000 // Milliseconds; or 0 for unlimited

struct tap_driver {
    libusb_device_handle * handle;
};

struct tap_driver * tap_driver_create(void) {
    int rc = libusb_init(NULL);
    if (rc < 0) {
        PERROR("Unable to initialize libusb");
        return NULL;
    }

    struct tap_driver * driver = calloc(1, sizeof *driver);
    if (driver == NULL) return NULL;

    driver->handle = libusb_open_device_with_vid_pid(NULL, VENDOR_ID, PRODUCT_ID);
    if (driver->handle == NULL) {
        PERROR("Unable to open device %04x:%04x", VENDOR_ID, PRODUCT_ID);
        goto fail;
    }

    return driver;
fail:
    free(driver);
    return NULL;
}

void tap_driver_destroy(struct tap_driver * driver) {
    libusb_close(driver->handle);
    free(driver);
}

int tap_driver_heartbeat(struct tap_driver * driver, uint16_t ticks) {
    int rc = libusb_control_transfer(driver->handle,
            LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE,
            CTRL_HEARTBEAT, ticks, 0,
            NULL, 0, TIMEOUT);
    if (rc == 0) return 0;
    return -1;
}

int tap_driver_set_led(struct tap_driver * driver, bool on) {
    int rc = libusb_control_transfer(driver->handle,
            LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE,
            CTRL_SET_LED, on, 0,
            NULL, 0, TIMEOUT);
    if (rc == 0) return 0;
    return -1;
}

int tap_driver_set_relays(struct tap_driver * driver, uint16_t value) {
    int rc = libusb_control_transfer(driver->handle,
            LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE,
            CTRL_SET_RELAYS, value, 0,
            NULL, 0, TIMEOUT);
    if (rc == 0) return 0;
    return -1;
}

int tap_driver_set_fault(struct tap_driver * driver, uint16_t value) {
    int rc = libusb_control_transfer(driver->handle,
            LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE,
            CTRL_SET_FAULT, value, 0,
            NULL, 0, TIMEOUT);
    if (rc == 0) return 0;
    return -1;
}
