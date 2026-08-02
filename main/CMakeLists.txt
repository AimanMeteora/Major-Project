idf_component_register(
    SRCS 
        "main.c"
        # Include your local source files if implemented in main component:
        # "memory.c"
        # "llm.c"
        # "agent.c"
        # "channel.c"
    INCLUDE_DIRS 
        "."
        # Include relative path to header directory if stored elsewhere (e.g., "include")
    REQUIRES 
        driver
        zclaw
        nvs_flash
        console
        esp_wifi
        esp_event
        esp_netif
        mbedtls
        freertos
        esp_system
)
