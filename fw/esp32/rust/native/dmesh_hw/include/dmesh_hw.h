#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t dmesh_ws2812_write(uint8_t gpio, uint8_t red, uint8_t green,
                           uint8_t blue);

#ifdef __cplusplus
}
#endif
