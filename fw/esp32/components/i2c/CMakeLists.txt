idf_component_register(SRCS "i2ctools.c"
                    INCLUDE_DIRS "."
            REQUIRES bt console driver esp_driver_i2c nvs_flash )
