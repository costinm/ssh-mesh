idf_component_register(SRCS "cmd_gpio.c"
                    INCLUDE_DIRS "."
            REQUIRES console esp_driver_gpio)
