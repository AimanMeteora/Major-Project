# ZClaw Authentication System

This document describes the authentication and access-control subsystem built into the ZClaw ESP32 console firmware (`auth_console.c`). It covers how the system maps to core CIS (Center for Internet Security) hardening principles, the console command reference, and configuration details.

## CIS Principle Mapping

| CIS Principle | ZClaw Implementation | Security Benefit |
|---|---|---|
| **Authentication** | Username/password login (`login <user> <pass>`), verified against a salted SHA-256 hash stored in NVS | Prevents unauthorized access to the console and connected AI agent |
| **Least Privilege** | Two roles — `ROLE_USER` and `ROLE_ADMIN` — gate sensitive commands (`user_add`, `user_upd`, `user_del`, `user_list`, `see_logs`) behind admin-only checks | Limits which accounts can run privileged or destructive commands |
| **Session Timeout** | Background `inactivity_watchdog_task` checks every second and force-logs-out any session idle for 60+ seconds | Prevents abandoned or forgotten sessions from being hijacked |
| **Password Policy** | `validate_password_policy()` enforces a 12-character minimum plus required uppercase, lowercase, digit, and symbol characters | Reduces risk of weak, guessable, or reused credentials |
| **Rate Limiting** | After 5 consecutive failed logins, the console locks out further attempts for 15 seconds (`MAX_FAILED_ATTEMPTS`, `LOCKOUT_DURATION_MS`) | Slows down and discourages brute-force login attacks |

## Additional Security Controls

Beyond the core CIS mapping above, the implementation includes:

- **Salted password hashing** — Each account gets a random 16-byte salt (`esp_fill_random`) combined with SHA-256 (via mbedTLS) to produce a 32-byte hash. Plaintext passwords are never stored.
- **Persistent credential storage** — The user database is persisted to NVS flash (`storage` namespace, `user_db` key) so accounts survive reboot.
- **Audit logging** — Up to the last 10 authentication events (success/failure, username, device uptime) are tracked in a circular buffer and viewable via `see_logs` (admin only).
- **Self-protection on deletion** — Admins cannot delete the account they are currently logged in as (`user_del`).
- **Mutex-protected session state** — All session/role reads and writes are guarded by a FreeRTOS mutex (`session_mutex`) to prevent race conditions across tasks.

## Console Command Reference

| Command | Access Level | Description |
|---|---|---|
| `login <user> <pass>` | Public | Authenticate and start a session |
| `logout` | Any active session | End the current session |
| `chat <message>` | User / Admin | Send a message to the ZClaw AI agent |
| `toggle_relay <pin>` | User / Admin | Toggle the state of a configured GPIO pin |
| `pin_status <pin>` | Public | Read the current state of a GPIO pin |
| `user_add <user> <pass> <admin\|user>` | Admin | Create a new account |
| `user_upd <user> <pass> <admin\|user>` | Admin | Update a password and/or role for an existing account |
| `user_del <user>` | Admin | Remove an account (cannot delete your own active session) |
| `user_list` | Admin | List all registered accounts and their roles |
| `see_logs` | Admin | Display the recent authentication audit trail |

## Configuration Reference

| Setting | Value | Constant |
|---|---|---|
| Max user accounts | 10 | `MAX_USERS` |
| Salt size | 16 bytes | `SALT_SIZE` |
| Hash size (SHA-256) | 32 bytes | `HASH_SIZE` |
| Session inactivity timeout | 60 seconds | `INACTIVITY_TIMEOUT_MS` |
| Max failed login attempts | 5 | `MAX_FAILED_ATTEMPTS` |
| Lockout duration | 15 seconds | `LOCKOUT_DURATION_MS` |
| Max audit log entries | 10 (circular buffer) | `MAX_AUDIT_LOGS` |
| Minimum password length | 12 characters | enforced in `validate_password_policy()` |

## Default Accounts

On first boot (when no user database exists in NVS yet), two default accounts are seeded:

| Username | Default Password | Role |
|---|---|---|
| `admin` | `Admin_12345!` | Admin |
| `operator` | `Operator_123!` | User |

> **⚠️ Important:** Change both default passwords immediately after first boot using `user_upd`. Shipping or deploying a device with default credentials intact defeats the purpose of the authentication system.

## Known Limitations / Hardening Notes

These are worth addressing before treating this as production-grade:

- **Wi-Fi credentials are hardcoded** in source (`WIFI_SSID` / `WIFI_PASS` placeholders) — move these to NVS or a provisioning flow rather than compiling them into firmware.
- **No password hashing iteration/stretching** — a single round of salted SHA-256 is used rather than a slow KDF (e.g., PBKDF2, bcrypt, Argon2), which would better resist offline brute-force if the NVS user database is ever extracted.
- **Rate limiting is global, not per-user** — a single `failed_attempts` counter locks out the whole console rather than tracking attempts per username or per source.
- **Audit log is volatile** — the audit trail (`audit_logs`) is not persisted to NVS, so history resets on reboot.
- **API key seeding** — `inject_dummy_api_key_if_missing()` writes a placeholder API key to NVS if none is set; ensure this is replaced with a real key before use in any non-test environment.

## Project Contributors
- **Aiman Yusuf** -  https://github.com/AimanMeteora
- **Jeannie Pang** - 
