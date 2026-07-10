idf_component_register(SRCS "lora.c" "lora_drv.c"
                    INCLUDE_DIRS .
            REQUIRES console esp_driver_gpio esp_driver_spi l3dmesh nvs_flash
                    )
