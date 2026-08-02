file(GLOB_RECURSE ZCLAW_SRCS "main/*.c" "*.c")
list(FILTER ZCLAW_SRCS EXCLUDE REGEX ".*/test/.*")
idf_component_register(
    SRCS ${ZCLAW_SRCS}
    INCLUDE_DIRS "." "main" 
    REQUIRES 
        nvs_flash
        driver
        mbedtls
        console
        zclaw
        json
        esp_timer
        esp_netif
        esp_http_client
        esp_wifi
        esp_event
        esp-tls
        bootloader_support
        app_update
)
