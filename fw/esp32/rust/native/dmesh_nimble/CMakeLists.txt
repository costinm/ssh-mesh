idf_component_register(
    SRCS "dmesh_nimble.c" "../dmesh_hw/dmesh_hw.c"
    INCLUDE_DIRS "include" "../dmesh_hw/include"
    REQUIRES bt nvs_flash esp_driver_rmt
)
