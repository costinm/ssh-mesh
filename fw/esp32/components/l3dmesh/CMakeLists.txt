idf_component_register(SRCS
        "dmesh.c"
        "cmd_system.c"
        "dmpeers.cpp"
                    INCLUDE_DIRS .
                    REQUIRES console esp-nan-aware esp_driver_gpio esp_driver_uart esp_pm esp_timer esp_wifi nvs_flash spi_flash)
