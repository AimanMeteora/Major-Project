#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "esp_system.h"
#include "esp_log.h"
#include "esp_console.h"
#include "esp_vfs_dev.h"
#include "driver/uart.h"
#include "linenoise/linenoise.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_random.h"
#include "mbedtls/md.h"
#include "driver/gpio.h"

/* FreeRTOS Components */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"

/* Network & Wi-Fi Headers */
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_wifi.h"

/* Subsystem Headers */
#include "memory.h"
#include "llm.h"
#include "agent.h"
#include "channel.h"

static const char *TAG = "auth_console";

/* -------------------------------------------------------------------------- */
/* Wi-Fi Credentials Configuration                                            */
/* -------------------------------------------------------------------------- */
#define WIFI_SSID      "WiFi SSID"
#define WIFI_PASS      "WiFi Password"
#define WIFI_CONNECTED_BIT BIT0

static EventGroupHandle_t s_wifi_event_group;

/* -------------------------------------------------------------------------- */
/* Channel Message Types & Constants                                          */
/* -------------------------------------------------------------------------- */
#ifndef MSG_SOURCE_CHANNEL
#define MSG_SOURCE_CHANNEL 0
#endif

typedef struct {
    char text[512];
    int source;
} channel_msg_t;

typedef struct {
    char text[1024];
} channel_output_msg_t;

/* -------------------------------------------------------------------------- */
/* Storage & Security Configuration                                          */
/* -------------------------------------------------------------------------- */
#define AUTH_NVS_NAMESPACE "storage"
#define NVS_KEY_USERS "user_db"

#define MAX_USERS 10
#define SALT_SIZE 16
#define HASH_SIZE 32      
#define INACTIVITY_TIMEOUT_MS (60 * 1000)

/* Rate Limiting Rules */
#define MAX_FAILED_ATTEMPTS 5
#define LOCKOUT_DURATION_MS (15 * 1000)

/* Audit Logging Rules */
#define MAX_AUDIT_LOGS 10

typedef enum {
    ROLE_NONE,
    ROLE_USER,
    ROLE_ADMIN
} user_role_t;

typedef struct {
    char username[32];
    uint8_t salt[SALT_SIZE];  
    uint8_t hash[HASH_SIZE];  
    user_role_t role;
    bool in_use;
} user_t;

typedef struct {
    char username[32];
    bool is_success;
    uint32_t uptime_seconds;
    bool valid;
} audit_log_t;

static user_t user_db[MAX_USERS];
static user_role_t current_role = ROLE_NONE;
static char current_user[32] = {0};

static SemaphoreHandle_t session_mutex = NULL;
static TickType_t last_activity_tick = 0;
static TaskHandle_t logout_task_handle = NULL;

/* Rate limiting variables */
static int failed_attempts = 0;
static TickType_t lockout_end_tick = 0;

/* Audit log variables */
static audit_log_t audit_logs[MAX_AUDIT_LOGS];
static int next_log_index = 0;
static int total_logged_events = 0;

/* Queue handles for zclaw integration */
static QueueHandle_t s_input_queue = NULL;
static QueueHandle_t s_channel_output_queue = NULL;
static QueueHandle_t s_telegram_output_queue = NULL;

/* -------------------------------------------------------------------------- */
/* GPIO Configuration                                                         */
/* -------------------------------------------------------------------------- */
static const gpio_num_t ALL_GPIO_PINS[] = {
    GPIO_NUM_0,  GPIO_NUM_2,  GPIO_NUM_4,  GPIO_NUM_5,
    GPIO_NUM_12, GPIO_NUM_13, GPIO_NUM_14, GPIO_NUM_15,
    GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_21
};
#define TOTAL_PINS (sizeof(ALL_GPIO_PINS) / sizeof(ALL_GPIO_PINS[0]))

/* -------------------------------------------------------------------------- */
/* Cryptographic & Helper Functions                                           */
/* -------------------------------------------------------------------------- */
static bool is_authorized(user_role_t required_role) {
    return (current_role >= required_role && current_role != ROLE_NONE);
}

static bool is_valid_pin(int pin_num) {
    for (size_t i = 0; i < TOTAL_PINS; i++) {
        if ((int)ALL_GPIO_PINS[i] == pin_num) return true;
    }
    return false;
}

static void reset_inactivity_timer(void) {
    last_activity_tick = xTaskGetTickCount();
}

static bool validate_password_policy(const char *password) {
    size_t length = strlen(password);
    if (length < 12) {
        printf("Password Error: Must be at least 12 characters long.\n");
        return false;
    }

    bool has_upper = false, has_lower = false, has_digit = false, has_special = false;
    for (size_t i = 0; i < length; i++) {
        char c = password[i];
        if (isupper((unsigned char)c)) has_upper = true;
        else if (islower((unsigned char)c)) has_lower = true;
        else if (isdigit((unsigned char)c)) has_digit = true;
        else if (ispunct((unsigned char)c) || c == ' ') has_special = true;
    }

    if (!has_upper || !has_lower || !has_digit || !has_special) {
        printf("Password Error: Must include uppercase, lowercase, numbers, and symbols.\n");
        return false;
    }

    return true;
}

static void hash_password(const char *password, const uint8_t *salt, uint8_t *output_hash) {
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char *)password, strlen(password));
    mbedtls_md_update(&ctx, (const unsigned char *)salt, SALT_SIZE);
    mbedtls_md_finish(&ctx, output_hash);
    mbedtls_md_free(&ctx);
}

static void generate_salt(uint8_t *salt_buffer) {
    esp_fill_random(salt_buffer, SALT_SIZE);
}

static void record_audit_event(const char *username, bool success) {
    strncpy(audit_logs[next_log_index].username, username, sizeof(audit_logs[next_log_index].username) - 1);
    audit_logs[next_log_index].is_success = success;
    audit_logs[next_log_index].uptime_seconds = (xTaskGetTickCount() * portTICK_PERIOD_MS) / 1000;
    audit_logs[next_log_index].valid = true;

    next_log_index = (next_log_index + 1) % MAX_AUDIT_LOGS;
    total_logged_events++;
}

static void save_user_db_to_nvs(void) {
    nvs_handle_t my_handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &my_handle);
    if (err == ESP_OK) {
        err = nvs_set_blob(my_handle, NVS_KEY_USERS, user_db, sizeof(user_db));
        if (err == ESP_OK) {
            nvs_commit(my_handle);
        }
        nvs_close(my_handle);
    }
}

/* -------------------------------------------------------------------------- */
/* Wi-Fi Initialization & Networking                                          */
/* -------------------------------------------------------------------------- */
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG, "Reconnecting to Wi-Fi...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Connected with IP: " IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(void) {
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Waiting for Wi-Fi connection...");
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
    ESP_LOGI(TAG, "Wi-Fi connected successfully.");
}

static void inject_dummy_api_key_if_missing(void) {
    nvs_handle_t handle;
    if (nvs_open("storage", NVS_READWRITE, &handle) == ESP_OK) {
        size_t required_size = 0;
        esp_err_t err = nvs_get_str(handle, "api_key", NULL, &required_size);
        if (err != ESP_OK || required_size <= 1) {
            nvs_set_str(handle, "api_key", "ollama_local");
            nvs_commit(handle);
            ESP_LOGI("NVS_SEED", "Seeded dummy API key ('ollama_local') into NVS.");
        }
        nvs_close(handle);
    }
}

/* -------------------------------------------------------------------------- */
/* FreeRTOS Background Tasks                                                 */
/* -------------------------------------------------------------------------- */
static void zclaw_response_task(void *pvParameters) {
    channel_output_msg_t msg;
    while (1) {
        if (xQueueReceive(s_channel_output_queue, &msg, portMAX_DELAY) == pdTRUE) {
            printf("\n[zclaw]: %s\n\n", msg.text);
            printf("guest@esp32> ");
            fflush(stdout);
        }
    }
}

static void inactivity_watchdog_task(void *pvParameters) {
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        xSemaphoreTake(session_mutex, portMAX_DELAY);
        if (current_role != ROLE_NONE) {
            TickType_t now = xTaskGetTickCount();
            if ((now - last_activity_tick) * portTICK_PERIOD_MS >= INACTIVITY_TIMEOUT_MS) {
                printf("\n\n[Security Notice] Session timed out due to inactivity. Logged out user '%s'.\n", current_user);
                current_role = ROLE_NONE;
                memset(current_user, 0, sizeof(current_user));
                printf("guest@esp32> ");
                fflush(stdout);
            }
        }
        xSemaphoreGive(session_mutex);
    }
}

/* -------------------------------------------------------------------------- */
/* Database Initialization                                                    */
/* -------------------------------------------------------------------------- */
static void init_user_db(void) {
    nvs_handle_t my_handle;
    size_t required_size = sizeof(user_db);
    bool loaded_from_nvs = false;

    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        if (nvs_get_blob(my_handle, NVS_KEY_USERS, user_db, &required_size) == ESP_OK && required_size == sizeof(user_db)) {
            loaded_from_nvs = true;
        }
        nvs_close(my_handle);
    }

    if (!loaded_from_nvs) {
        memset(user_db, 0, sizeof(user_db));
        
        strncpy(user_db[0].username, "admin", sizeof(user_db[0].username) - 1);
        generate_salt(user_db[0].salt);
        hash_password("Admin_12345!", user_db[0].salt, user_db[0].hash); 
        user_db[0].role = ROLE_ADMIN;
        user_db[0].in_use = true;

        strncpy(user_db[1].username, "operator", sizeof(user_db[1].username) - 1);
        generate_salt(user_db[1].salt);
        hash_password("Operator_123!", user_db[1].salt, user_db[1].hash);  
        user_db[1].role = ROLE_USER;
        user_db[1].in_use = true;
        
        save_user_db_to_nvs();
    }
}

/* -------------------------------------------------------------------------- */
/* Console Command Handlers                                                   */
/* -------------------------------------------------------------------------- */
static int do_login(int argc, char **argv) {
    xSemaphoreTake(session_mutex, portMAX_DELAY);
    reset_inactivity_timer(); 
    TickType_t current_tick = xTaskGetTickCount();

    if (failed_attempts >= MAX_FAILED_ATTEMPTS) {
        if (current_tick < lockout_end_tick) {
            TickType_t remaining_ticks = lockout_end_tick - current_tick;
            uint32_t remaining_seconds = (remaining_ticks * portTICK_PERIOD_MS) / 1000 + 1;
            printf("Access Blocked: Too many failed logins. Please wait %lu more seconds.\n", remaining_seconds);
            xSemaphoreGive(session_mutex);
            return 1;
        } else {
            failed_attempts = 0;
        }
    }

    if (argc < 3) {
        printf("Usage: login <username> <password>\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }
    if (current_role != ROLE_NONE) {
        printf("Already logged in as '%s'. Logout first.\n", current_user);
        xSemaphoreGive(session_mutex);
        return 1;
    }

    const char *input_username = argv[1];
    const char *input_password = argv[2];

    for (int i = 0; i < MAX_USERS; i++) {
        if (user_db[i].in_use && strcmp(user_db[i].username, input_username) == 0) {
            uint8_t verification_hash[HASH_SIZE];
            hash_password(input_password, user_db[i].salt, verification_hash);

            if (memcmp(user_db[i].hash, verification_hash, HASH_SIZE) == 0) {
                current_role = user_db[i].role;
                strncpy(current_user, user_db[i].username, sizeof(current_user) - 1);
                printf("Login successful! Role: %s\n", (current_role == ROLE_ADMIN) ? "Admin" : "User");
                
                record_audit_event(input_username, true);
                failed_attempts = 0; 
                reset_inactivity_timer(); 
                xSemaphoreGive(session_mutex);
                return 0;
            }
            break; 
        }
    }

    failed_attempts++;
    record_audit_event(input_username, false);

    ESP_LOGW(TAG, "SECURITY ALERT: Failed login attempt for user '%s'. Consecutive fails: %d.", input_username, failed_attempts);
    printf("Error: Invalid username or password. (Failed tries: %d/%d)\n", failed_attempts, MAX_FAILED_ATTEMPTS);

    if (failed_attempts >= MAX_FAILED_ATTEMPTS) {
        lockout_end_tick = xTaskGetTickCount() + pdMS_TO_TICKS(LOCKOUT_DURATION_MS);
        ESP_LOGW(TAG, "SECURITY LOCKOUT TRIPPED: System blocking console input for 15 seconds.");
        printf("[ALERT] Security Threshold Reached! Terminal locked for 15 seconds.\n");
    }

    xSemaphoreGive(session_mutex);
    return 1;
}

static int do_logout(int argc, char **argv) {
    xSemaphoreTake(session_mutex, portMAX_DELAY);
    if (current_role == ROLE_NONE) {
        printf("No active session.\n");
        xSemaphoreGive(session_mutex);
        return 0;
    }
    printf("Logged out user '%s'.\n", current_user);
    current_role = ROLE_NONE;
    memset(current_user, 0, sizeof(current_user));
    xSemaphoreGive(session_mutex);
    return 0;
}

static int do_chat(int argc, char **argv) {
    xSemaphoreTake(session_mutex, portMAX_DELAY);
    if (current_role == ROLE_NONE) {
        printf("Error: Authentication required. Please log in first.\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }
    reset_inactivity_timer();
    xSemaphoreGive(session_mutex);

    if (argc < 2) {
        printf("Usage: chat <message>\n");
        return 1;
    }

    char message[256] = {0};
    size_t remaining_space = sizeof(message) - 1;

    for (int i = 1; i < argc; i++) {
        size_t arg_len = strlen(argv[i]);
        if (arg_len + (i < argc - 1 ? 1 : 0) > remaining_space) {
            printf("Error: Message payload exceeds size limit.\n");
            return 1;
        }
        strncat(message, argv[i], remaining_space);
        remaining_space -= arg_len;

        if (i < argc - 1) {
            strncat(message, " ", remaining_space);
            remaining_space -= 1;
        }
    }

    channel_msg_t msg;
    snprintf(msg.text, sizeof(msg.text), "%s", message);
    msg.source = MSG_SOURCE_CHANNEL;

    if (xQueueSend(s_input_queue, &msg, pdMS_TO_TICKS(1000)) == pdTRUE) {
        printf("Message sent to zclaw agent...\n");
    } else {
        printf("Failed to queue message to zclaw.\n");
    }

    return 0;
}

static int do_user_add(int argc, char **argv) {
    xSemaphoreTake(session_mutex, portMAX_DELAY);
    reset_inactivity_timer();
    if (!is_authorized(ROLE_ADMIN)) {
        printf("Access Denied: Admin role required.\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }
    if (argc < 4) {
        printf("Usage: user_add <username> <password> <role: admin|user>\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }

    const char *username = argv[1];
    const char *password = argv[2];
    user_role_t target_role = ROLE_USER;
    if (strcmp(argv[3], "admin") == 0) target_role = ROLE_ADMIN;

    for (int i = 0; i < MAX_USERS; i++) {
        if (user_db[i].in_use && strcmp(user_db[i].username, username) == 0) {
            printf("Error: User '%s' already exists. Use 'user_upd' to change passwords.\n", username);
            xSemaphoreGive(session_mutex);
            return 1;
        }
    }

    if (!validate_password_policy(password)) {
        printf("Account creation aborted due to weak password complexity.\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }

    for (int i = 0; i < MAX_USERS; i++) {
        if (!user_db[i].in_use) {
            strncpy(user_db[i].username, username, sizeof(user_db[i].username) - 1);
            generate_salt(user_db[i].salt);
            hash_password(password, user_db[i].salt, user_db[i].hash);
            user_db[i].role = target_role;
            user_db[i].in_use = true;
            printf("User '%s' created successfully.\n", username);
            save_user_db_to_nvs();
            xSemaphoreGive(session_mutex);
            return 0;
        }
    }
    printf("Error: User database is full.\n");
    xSemaphoreGive(session_mutex);
    return 1;
}

static int do_user_upd(int argc, char **argv) {
    xSemaphoreTake(session_mutex, portMAX_DELAY);
    reset_inactivity_timer();
    if (!is_authorized(ROLE_ADMIN)) {
        printf("Access Denied: Admin role required to update users.\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }

    if (argc < 4) {
        printf("Usage: user_upd <username> <new_password> <new_role: admin|user>\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }

    const char *username = argv[1];
    const char *new_password = argv[2];
    user_role_t new_role = ROLE_USER;
    if (strcmp(argv[3], "admin") == 0) new_role = ROLE_ADMIN;

    if (!validate_password_policy(new_password)) {
        printf("Update aborted: Password fails complexity standards.\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }

    for (int i = 0; i < MAX_USERS; i++) {
        if (user_db[i].in_use && strcmp(user_db[i].username, username) == 0) {
            generate_salt(user_db[i].salt);
            hash_password(new_password, user_db[i].salt, user_db[i].hash);
            user_db[i].role = new_role;
            printf("User account '%s' successfully updated.\n", username);
            save_user_db_to_nvs();
            xSemaphoreGive(session_mutex);
            return 0;
        }
    }

    printf("Error: User '%s' not found.\n", username);
    xSemaphoreGive(session_mutex);
    return 1;
}

static int do_user_del(int argc, char **argv) {
    xSemaphoreTake(session_mutex, portMAX_DELAY);
    reset_inactivity_timer();
    if (!is_authorized(ROLE_ADMIN)) {
        printf("Access Denied: Admin role required.\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }
    if (argc < 2) {
        printf("Usage: user_del <username>\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }

    const char *username = argv[1];
    if (strcmp(current_user, username) == 0) {
        printf("Error: You cannot delete your own active session account.\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }

    for (int i = 0; i < MAX_USERS; i++) {
        if (user_db[i].in_use && strcmp(user_db[i].username, username) == 0) {
            user_db[i].in_use = false;
            memset(&user_db[i], 0, sizeof(user_t));
            printf("User '%s' deleted successfully.\n", username);
            save_user_db_to_nvs();
            xSemaphoreGive(session_mutex);
            return 0;
        }
    }
    printf("Error: User '%s' not found.\n", username);
    xSemaphoreGive(session_mutex);
    return 1;
}

static int do_user_list(int argc, char **argv) {
    xSemaphoreTake(session_mutex, portMAX_DELAY);
    reset_inactivity_timer();
    if (!is_authorized(ROLE_ADMIN)) {
        printf("Access Denied: Admin role required.\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }

    printf("\n%-16s %-12s\n", "Username", "Role");
    printf("-----------------------------------\n");
    for (int i = 0; i < MAX_USERS; i++) {
        if (user_db[i].in_use) {
            printf("%-16s %-12s\n", user_db[i].username, (user_db[i].role == ROLE_ADMIN) ? "admin" : "user");
        }
    }
    printf("\n");
    xSemaphoreGive(session_mutex);
    return 0;
}

static int do_see_logs(int argc, char **argv) {
    xSemaphoreTake(session_mutex, portMAX_DELAY);
    reset_inactivity_timer();
    if (!is_authorized(ROLE_ADMIN)) {
        printf("Access Denied: Admin privileges required to view logs.\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }

    printf("\n================= SECURITY AUDIT REPORT =================\n");
    int display_count = (total_logged_events < MAX_AUDIT_LOGS) ? total_logged_events : MAX_AUDIT_LOGS;
    
    if (display_count == 0) {
        printf("No authentication events recorded during this boot cycle.\n");
    } else {
        int start_index = (total_logged_events < MAX_AUDIT_LOGS) ? 0 : next_log_index;
        for (int i = 0; i < display_count; i++) {
            int current_index = (start_index + i) % MAX_AUDIT_LOGS;
            audit_log_t *log = &audit_logs[current_index];

            uint32_t min = log->uptime_seconds / 60;
            uint32_t sec = log->uptime_seconds % 60;

            printf("Log no.%d (%s) User: %s Time: (%lu min %lu sec uptime)\n", 
                   i + 1, log->is_success ? "Success" : "Fail", log->username, min, sec);
        }
    }
    printf("=========================================================\n\n");
    xSemaphoreGive(session_mutex);
    return 0;
}

static int do_toggle_relay(int argc, char **argv) {
    xSemaphoreTake(session_mutex, portMAX_DELAY);
    reset_inactivity_timer(); 
    if (!is_authorized(ROLE_USER)) {
        printf("Access Denied: Authentication required.\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }

    if (argc < 2) {
        printf("Usage: toggle_relay <pin_number>\n");
        xSemaphoreGive(session_mutex);
        return 1;
    }

    int target_pin = atoi(argv[1]);

    if (!is_valid_pin(target_pin)) {
        printf("Error: GPIO %d is not configured or is protected.\n", target_pin);
        xSemaphoreGive(session_mutex);
        return 1;
    }

    int current_state = gpio_get_level((gpio_num_t)target_pin);
    int next_state = !current_state;
    
    gpio_set_level((gpio_num_t)target_pin, next_state);
    printf("GPIO %d toggled to: %s by '%s'\n", target_pin, next_state ? "HIGH" : "LOW", current_user);

    xSemaphoreGive(session_mutex);
    return 0;
}

static int do_pin_status(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: pin_status <pin_number>\n");
        return 1;
    }

    int target_pin = atoi(argv[1]);

    if (!is_valid_pin(target_pin)) {
        printf("Error: GPIO %d is invalid.\n", target_pin);
        return 1;
    }

    int current_state = gpio_get_level((gpio_num_t)target_pin);
    printf("GPIO %d State: %s\n", target_pin, current_state ? "HIGH (3.3V)" : "LOW (0V)");
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Command Registration & Main                                                */
/* -------------------------------------------------------------------------- */
static void register_commands(void) {
    const esp_console_cmd_t login_cmd  = { .command = "login", .help = "Login: login <user> <pass>", .func = &do_login };
    const esp_console_cmd_t logout_cmd = { .command = "logout", .help = "Logout active session", .func = &do_logout };
    const esp_console_cmd_t chat_cmd   = { .command = "chat", .help = "Send message to AI: chat <msg>", .func = &do_chat };
    const esp_console_cmd_t add_cmd    = { .command = "user_add", .help = "Create user: user_add <user> <pass> <admin|user>", .func = &do_user_add };
    const esp_console_cmd_t upd_cmd    = { .command = "user_upd", .help = "Modify user: user_upd <user> <pass> <admin|user>", .func = &do_user_upd };
    const esp_console_cmd_t del_cmd    = { .command = "user_del", .help = "Delete user: user_del <user>", .func = &do_user_del };
    const esp_console_cmd_t list_cmd   = { .command = "user_list", .help = "List users", .func = &do_user_list };
    const esp_console_cmd_t logs_cmd   = { .command = "see_logs", .help = "View audit traces", .func = &do_see_logs };
    const esp_console_cmd_t relay_cmd  = { .command = "toggle_relay", .help = "Toggle pin state: toggle_relay <pin>", .func = &do_toggle_relay };
    const esp_console_cmd_t status_cmd = { .command = "pin_status", .help = "Check pin voltage: pin_status <pin>", .func = &do_pin_status };

    ESP_ERROR_CHECK(esp_console_cmd_register(&login_cmd));
    ESP_ERROR_CHECK(esp_console_cmd_register(&logout_cmd));
    ESP_ERROR_CHECK(esp_console_cmd_register(&chat_cmd));
    ESP_ERROR_CHECK(esp_console_cmd_register(&add_cmd));
    ESP_ERROR_CHECK(esp_console_cmd_register(&upd_cmd));
    ESP_ERROR_CHECK(esp_console_cmd_register(&del_cmd));
    ESP_ERROR_CHECK(esp_console_cmd_register(&list_cmd));
    ESP_ERROR_CHECK(esp_console_cmd_register(&logs_cmd));
    ESP_ERROR_CHECK(esp_console_cmd_register(&relay_cmd));
    ESP_ERROR_CHECK(esp_console_cmd_register(&status_cmd));
}

void app_main(void) {
    session_mutex = xSemaphoreCreateMutex();
    assert(session_mutex != NULL);

    // 1. Initialize NVS Flash
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // 2. Connect Wi-Fi
    wifi_init_sta();

    // 3. Inject missing dummy keys
    inject_dummy_api_key_if_missing();

    // 4. Initialize Subsystems & Data Structures
    memory_init();
    llm_init();
    init_user_db();
    memset(audit_logs, 0, sizeof(audit_logs));

    // 5. Create FreeRTOS Queues & Agent Runtime
    s_input_queue = xQueueCreate(10, sizeof(channel_msg_t));
    s_channel_output_queue = xQueueCreate(10, sizeof(channel_output_msg_t));
    s_telegram_output_queue = xQueueCreate(10, sizeof(channel_output_msg_t));

    agent_start(s_input_queue, s_channel_output_queue, s_telegram_output_queue);

    // 6. Reset Hardware Pin States
    for (size_t i = 0; i < TOTAL_PINS; i++) {
        gpio_reset_pin(ALL_GPIO_PINS[i]);
        gpio_set_direction(ALL_GPIO_PINS[i], GPIO_MODE_INPUT_OUTPUT);
        gpio_set_level(ALL_GPIO_PINS[i], 0);
    }

    // 7. Launch Background Tasks
    xTaskCreate(inactivity_watchdog_task, "inactivity_watchdog", 3072, NULL, 5, &logout_task_handle);
    xTaskCreate(zclaw_response_task, "zclaw_resp", 12000, NULL, 5, NULL);

    // 8. Launch Console REPL Framework
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    repl_config.prompt = "esp32@esp32> ";
    repl_config.max_cmdline_length = 256;

    register_commands();

    esp_console_dev_uart_config_t uart_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    uart_config.channel = CONFIG_ESP_CONSOLE_UART_NUM;
    uart_config.baud_rate = 115200;

    esp_console_repl_t *repl = NULL;
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&uart_config, &repl_config, &repl));

    printf("\n=======================================================\n");
    printf(" Welcome to Secure ESP32 Console + zclaw AI Runtime\n");
    printf(" System initialized successfully.\n");
    printf(" Usage: login <Username> <Password>.\n");
    printf("=======================================================\n\n");

    ESP_ERROR_CHECK(esp_console_start_repl(repl));
}
