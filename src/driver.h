#pragma once

#define TAP_DRIVER_RELAYS_MITM      0xAAAA
#define TAP_DRIVER_RELAYS_PASSTHRU  0x5555

struct tap_driver;

struct tap_driver * tap_driver_create();
void tap_driver_destroy();

int tap_driver_heartbeat(struct tap_driver * driver, uint16_t ticks);
int tap_driver_set_led(struct tap_driver * driver, bool on);
int tap_driver_set_relays(struct tap_driver * driver, uint16_t value);
int tap_driver_set_fault(struct tap_driver * driver, uint16_t value);
//int tap_driver_get_accel(struct tap_driver * driver);
