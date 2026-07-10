idf_component_register(SRCS "nan.c" "beacons.c"
                    INCLUDE_DIRS .
                    REQUIRES console esp_event esp_netif esp_timer esp_wifi lwip nvs_flash)
