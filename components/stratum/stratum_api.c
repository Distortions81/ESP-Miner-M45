/******************************************************************************
 *  *
 * References:
 *  1. Stratum Protocol - [link](https://reference.cash/mining/stratum-protocol)
 *****************************************************************************/

#include "stratum_api.h"
#include "cJSON.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "esp_transport.h"
#include "esp_transport_ssl.h"
#include "esp_transport_tcp.h"
#include "esp_crt_bundle.h"
#include "utils.h"
#include "esp_timer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>

#define TRANSPORT_TIMEOUT_MS 5000
#define BUFFER_SIZE 1024
#define MAX_EXTRANONCE_2_LEN 32
static const char * TAG = "stratum_api";

static char * json_rpc_buffer = NULL;
static size_t json_rpc_buffer_size = 0;
static int last_parsed_request_id = -1;

static RequestTiming request_timings[MAX_INFLIGHT_REQUESTS];
static bool initialized = false;

static void init_request_timings() {
    if (!initialized) {
        for (int i = 0; i < MAX_INFLIGHT_REQUESTS; i++) {
            request_timings[i].timestamp_us = 0;
            request_timings[i].request_id = -1;
            request_timings[i].tracking = false;
        }
        initialized = true;
    }
}

static RequestTiming* find_request_timing(int request_id) {
    if (request_id < 0) return NULL;
    for (int i = 0; i < MAX_INFLIGHT_REQUESTS; i++) {
        if (request_timings[i].tracking && request_timings[i].request_id == request_id) {
            return &request_timings[i];
        }
    }
    return NULL;
}

static RequestTiming* alloc_request_timing(int request_id) {
    if (request_id < 0) return NULL;
    // Reuse existing entry for this request_id.
    RequestTiming *existing = find_request_timing(request_id);
    if (existing) {
        return existing;
    }
    // Find a free slot.
    for (int i = 0; i < MAX_INFLIGHT_REQUESTS; i++) {
        if (!request_timings[i].tracking) {
            request_timings[i].request_id = request_id;
            return &request_timings[i];
        }
    }
    // Table full: skip timing to avoid collisions.
    return NULL;
}

void STRATUM_V1_stamp_tx(int request_id)
{
    init_request_timings();
    if (request_id >= 1) {
        RequestTiming *timing = alloc_request_timing(request_id);
        if (timing) {
            timing->timestamp_us = esp_timer_get_time();
            timing->tracking = true;
        }
    }
}

double STRATUM_V1_get_response_time_ms(int request_id)
{
    init_request_timings();
    if (request_id < 0) return -1.0;
    
    RequestTiming *timing = find_request_timing(request_id);
    if (!timing || !timing->tracking) {
        return -1.0;
    }
    
    double response_time = (esp_timer_get_time() - timing->timestamp_us) / 1000.0;
    timing->tracking = false;
    timing->request_id = -1;
    return response_time;
}

static void debug_stratum_tx(const char *);
int _parse_stratum_subscribe_result_message(const char * result_json_str, char ** extranonce, int * extranonce2_len);

static int stratum_sendf(esp_transport_handle_t transport, const char *fmt, ...)
{
    char msg[BUFFER_SIZE];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    debug_stratum_tx(msg);
    return esp_transport_write(transport, msg, strlen(msg), TRANSPORT_TIMEOUT_MS);
}

static const char *json_skip_ws(const char *p)
{
    while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
        p++;
    }
    return p;
}

static const char *json_skip_string(const char *p)
{
    if (*p != '"') {
        return NULL;
    }
    p++;
    bool escape = false;
    while (*p) {
        if (escape) {
            escape = false;
            p++;
            continue;
        }
        if (*p == '\\') {
            escape = true;
            p++;
            continue;
        }
        if (*p == '"') {
            return p + 1;
        }
        p++;
    }
    return NULL;
}

static const char *json_parse_string_dup(const char *p, char **out)
{
    p = json_skip_ws(p);
    if (*p != '"') {
        return NULL;
    }
    const char *start = p + 1;
    const char *end = json_skip_string(p);
    if (end == NULL) {
        return NULL;
    }
    size_t len = 0;
    bool escape = false;
    for (const char *r = start; r < end - 1; r++) {
        if (escape) {
            escape = false;
            len++;
            continue;
        }
        if (*r == '\\') {
            escape = true;
            continue;
        }
        len++;
    }
    char *buf = malloc(len + 1);
    if (!buf) {
        return NULL;
    }
    char *w = buf;
    escape = false;
    for (const char *r = start; r < end - 1; r++) {
        if (escape) {
            *w++ = *r;
            escape = false;
            continue;
        }
        if (*r == '\\') {
            escape = true;
            continue;
        }
        *w++ = *r;
    }
    *w = '\0';
    *out = buf;
    return end;
}

static const char *json_parse_int(const char *p, int *out)
{
    p = json_skip_ws(p);
    char *end = NULL;
    long value = strtol(p, &end, 10);
    if (end == p) {
        return NULL;
    }
    *out = (int)value;
    return end;
}

static const char *json_parse_uint32(const char *p, uint32_t *out)
{
    p = json_skip_ws(p);
    char *end = NULL;
    unsigned long value = strtoul(p, &end, 10);
    if (end == p) {
        return NULL;
    }
    *out = (uint32_t)value;
    return end;
}

static const char *json_parse_bool(const char *p, bool *out)
{
    p = json_skip_ws(p);
    if (strncmp(p, "true", 4) == 0) {
        *out = true;
        return p + 4;
    }
    if (strncmp(p, "false", 5) == 0) {
        *out = false;
        return p + 5;
    }
    return NULL;
}

static const char *json_find_key(const char *json, const char *key)
{
    size_t key_len = strlen(key);
    bool in_string = false;
    bool escape = false;
    for (const char *p = json; *p; p++) {
        if (in_string) {
            if (escape) {
                escape = false;
                continue;
            }
            if (*p == '\\') {
                escape = true;
                continue;
            }
            if (*p == '"') {
                in_string = false;
            }
            continue;
        }
        if (*p == '"') {
            if (strncmp(p + 1, key, key_len) == 0 && p[1 + key_len] == '"') {
                const char *q = p + 1 + key_len + 1;
                q = json_skip_ws(q);
                if (*q != ':') {
                    continue;
                }
                q++;
                return json_skip_ws(q);
            }
            in_string = true;
        }
    }
    return NULL;
}

static const char *json_skip_value(const char *p)
{
    p = json_skip_ws(p);
    if (*p == '"') {
        return json_skip_string(p);
    }
    if (*p == '{' || *p == '[') {
        char open = *p;
        char close = (open == '{') ? '}' : ']';
        int depth = 0;
        bool in_string = false;
        bool escape = false;
        for (; *p; p++) {
            if (in_string) {
                if (escape) {
                    escape = false;
                    continue;
                }
                if (*p == '\\') {
                    escape = true;
                    continue;
                }
                if (*p == '"') {
                    in_string = false;
                }
                continue;
            }
            if (*p == '"') {
                in_string = true;
                continue;
            }
            if (*p == open) {
                depth++;
            } else if (*p == close) {
                depth--;
                if (depth == 0) {
                    return p + 1;
                }
            }
        }
        return NULL;
    }
    if (strncmp(p, "true", 4) == 0) return p + 4;
    if (strncmp(p, "false", 5) == 0) return p + 5;
    if (strncmp(p, "null", 4) == 0) return p + 4;
    if ((*p >= '0' && *p <= '9') || *p == '-') {
        while (*p && (strchr("0123456789+-.eE", *p) != NULL)) {
            p++;
        }
        return p;
    }
    return NULL;
}

static const char *json_expect_char(const char *p, char c)
{
    p = json_skip_ws(p);
    if (*p != c) {
        return NULL;
    }
    return p + 1;
}

static const char *json_parse_hex_u32_from_string(const char *p, uint32_t *out)
{
    p = json_skip_ws(p);
    if (*p != '"') {
        return NULL;
    }
    p++; // skip opening quote

    uint32_t value = 0;
    bool has_digit = false;

    while (*p && *p != '"') {
        unsigned char c = (unsigned char)*p;
        uint8_t v;
        if (c >= '0' && c <= '9') {
            v = (uint8_t)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v = (uint8_t)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            v = (uint8_t)(c - 'A' + 10);
        } else {
            return NULL;
        }
        value = (value << 4) | v;
        has_digit = true;
        p++;
    }

    if (*p != '"' || !has_digit) {
        return NULL;
    }

    *out = value;
    return p + 1;
}

static const char *json_count_string_array(const char *p, size_t *count)
{
    p = json_expect_char(p, '[');
    if (!p) return NULL;
    size_t total = 0;
    for (;;) {
        p = json_skip_ws(p);
        if (*p == ']') {
            p++;
            break;
        }
        const char *next = json_skip_string(p);
        if (!next) {
            return NULL;
        }
        total++;
        p = json_skip_ws(next);
        if (*p == ',') {
            p++;
            continue;
        }
        if (*p == ']') {
            p++;
            break;
        }
        return NULL;
    }
    *count = total;
    return p;
}

static const char *json_parse_merkle_array(const char *p, mining_notify *new_work)
{
    size_t count = 0;
    const char *after = json_count_string_array(p, &count);
    if (!after) {
        return NULL;
    }
    if (count > MAX_MERKLE_BRANCHES) {
        ESP_LOGE(TAG, "Too many Merkle branches.");
        return NULL;
    }
    new_work->n_merkle_branches = count;
    new_work->merkle_branches = malloc(HASH_SIZE * count);
    if (!new_work->merkle_branches && count > 0) {
        return NULL;
    }
    p = json_expect_char(p, '[');
    if (!p) return NULL;
    size_t idx = 0;
    for (;;) {
        p = json_skip_ws(p);
        if (*p == ']') {
            p++;
            break;
        }
        char *branch = NULL;
        const char *next = json_parse_string_dup(p, &branch);
        if (!next) {
            return NULL;
        }
        if (idx < count) {
            hex2bin(branch, new_work->merkle_branches + HASH_SIZE * idx, HASH_SIZE);
        }
        free(branch);
        idx++;
        p = json_skip_ws(next);
        if (*p == ',') {
            p++;
            continue;
        }
        if (*p == ']') {
            p++;
            break;
        }
        return NULL;
    }
    return p;
}

static bool parse_notify_params_fast(const char *p, mining_notify *new_work)
{
    p = json_expect_char(p, '[');
    if (!p) return false;
    p = json_parse_string_dup(p, &new_work->job_id);
    if (!p) return false;
    p = json_expect_char(p, ',');
    if (!p) return false;
    p = json_parse_string_dup(p, &new_work->prev_block_hash);
    if (!p) return false;
    p = json_expect_char(p, ',');
    if (!p) return false;
    p = json_parse_string_dup(p, &new_work->coinbase_1);
    if (!p) return false;
    p = json_expect_char(p, ',');
    if (!p) return false;
    p = json_parse_string_dup(p, &new_work->coinbase_2);
    if (!p) return false;
    p = json_expect_char(p, ',');
    if (!p) return false;
    p = json_parse_merkle_array(p, new_work);
    if (!p) return false;
    p = json_expect_char(p, ',');
    if (!p) return false;
    p = json_parse_hex_u32_from_string(p, &new_work->version);
    if (!p) return false;
    p = json_expect_char(p, ',');
    if (!p) return false;
    p = json_parse_hex_u32_from_string(p, &new_work->target);
    if (!p) return false;
    p = json_expect_char(p, ',');
    if (!p) return false;
    p = json_parse_hex_u32_from_string(p, &new_work->ntime);
    if (!p) return false;
    p = json_expect_char(p, ',');
    if (!p) return false;
    bool clean_jobs = false;
    p = json_parse_bool(p, &clean_jobs);
    if (!p) return false;
    new_work->clean_jobs = clean_jobs;
    return true;
}

static bool parse_result_fast(StratumApiV1Message *message, const char *stratum_json, int parsed_id)
{
    const char *result = json_find_key(stratum_json, "result");
    if (!result) {
        return false;
    }

    if (parsed_id == STRATUM_ID_SUBSCRIBE && *result == '[') {
        const char *p = result;
        p = json_expect_char(p, '[');
        if (!p) return false;
        p = json_skip_value(p);
        if (!p) return false;
        p = json_expect_char(p, ',');
        if (!p) return false;
        char *extranonce = NULL;
        p = json_parse_string_dup(p, &extranonce);
        if (!p) return false;
        p = json_expect_char(p, ',');
        if (!p) {
            free(extranonce);
            return false;
        }
        int extranonce_len = 0;
        p = json_parse_int(p, &extranonce_len);
        if (!p) {
            free(extranonce);
            return false;
        }
        if (extranonce_len > MAX_EXTRANONCE_2_LEN) {
            ESP_LOGW(TAG, "Extranonce_2_len %d exceeds maximum %d, clamping to maximum",
                     extranonce_len, MAX_EXTRANONCE_2_LEN);
            extranonce_len = MAX_EXTRANONCE_2_LEN;
        }
        message->extranonce_str = extranonce;
        message->extranonce_2_len = extranonce_len;
        message->response_success = true;
        message->method = STRATUM_RESULT_SUBSCRIBE;
        return true;
    }

    if (*result == '{' && parsed_id == STRATUM_ID_CONFIGURE) {
        const char *mask = json_find_key(stratum_json, "version-rolling.mask");
        if (mask && *mask == '"') {
            uint32_t version_mask = 0;
            if (json_parse_hex_u32_from_string(mask, &version_mask)) {
                message->version_mask = version_mask;
                message->method = STRATUM_RESULT_VERSION_MASK;
                return true;
            }
        }
    }

    bool ok = false;
    const char *after_bool = json_parse_bool(result, &ok);
    if (after_bool) {
        message->response_success = ok;
        message->method = (parsed_id < 5) ? STRATUM_RESULT_SETUP : STRATUM_RESULT;
        if (!ok) {
            const char *reject = json_find_key(stratum_json, "reject-reason");
            if (reject && *reject == '"') {
                char *reason = NULL;
                if (json_parse_string_dup(reject, &reason)) {
                    message->error_str = reason;
                }
            }
        }
        return true;
    }

    const char *error = json_find_key(stratum_json, "error");
    if (error && strncmp(error, "null", 4) != 0) {
        message->response_success = false;
        message->method = (parsed_id < 5) ? STRATUM_RESULT_SETUP : STRATUM_RESULT;
        char *error_msg = NULL;
        if (*error == '[') {
            const char *p = error;
            p = json_expect_char(p, '[');
            if (p) {
                p = json_skip_value(p);
                if (p) {
                    p = json_expect_char(p, ',');
                    if (p) {
                        if (json_parse_string_dup(p, &error_msg)) {
                            message->error_str = error_msg;
                            return true;
                        }
                    }
                }
            }
        } else if (*error == '"') {
            if (json_parse_string_dup(error, &error_msg)) {
                message->error_str = error_msg;
                return true;
            }
        }
        if (!message->error_str) {
            message->error_str = strdup("unknown");
        }
        return true;
    }

    if (strncmp(result, "null", 4) == 0) {
        message->response_success = false;
        message->error_str = strdup("unknown");
        message->method = (parsed_id < 5) ? STRATUM_RESULT_SETUP : STRATUM_RESULT;
        return true;
    }

    return false;
}

static bool STRATUM_V1_parse_fast(StratumApiV1Message *message, const char *stratum_json)
{
    const char *id_val = json_find_key(stratum_json, "id");
    int parsed_id = -1;
    if (id_val && strncmp(id_val, "null", 4) != 0) {
        json_parse_int(id_val, &parsed_id);
    }
    last_parsed_request_id = parsed_id;
    message->message_id = parsed_id;

    const char *method_val = json_find_key(stratum_json, "method");
    if (method_val && *method_val == '"') {
        char *method = NULL;
        if (!json_parse_string_dup(method_val, &method) || !method) {
            free(method);
            return false;
        }
        if (strcmp("mining.notify", method) == 0) {
            message->method = MINING_NOTIFY;
            mining_notify *new_work = calloc(1, sizeof(mining_notify));
            if (!new_work) {
                free(method);
                return false;
            }
            const char *params = json_find_key(stratum_json, "params");
            if (!params || !parse_notify_params_fast(params, new_work)) {
                STRATUM_V1_free_mining_notify(new_work);
                free(method);
                return false;
            }
            new_work->coinbase_1_bin_len = strlen(new_work->coinbase_1) / 2;
            new_work->coinbase_2_bin_len = strlen(new_work->coinbase_2) / 2;
            new_work->coinbase_1_bin = malloc(new_work->coinbase_1_bin_len);
            new_work->coinbase_2_bin = malloc(new_work->coinbase_2_bin_len);
            if (new_work->coinbase_1_bin != NULL) {
                hex2bin(new_work->coinbase_1, new_work->coinbase_1_bin, new_work->coinbase_1_bin_len);
            }
            if (new_work->coinbase_2_bin != NULL) {
                hex2bin(new_work->coinbase_2, new_work->coinbase_2_bin, new_work->coinbase_2_bin_len);
            }
            message->mining_notification = new_work;
            free(method);
            return true;
        }
        if (strcmp("mining.set_difficulty", method) == 0) {
            message->method = MINING_SET_DIFFICULTY;
            const char *params = json_find_key(stratum_json, "params");
            if (!params) {
                free(method);
                return false;
            }
            params = json_expect_char(params, '[');
            if (!params) {
                free(method);
                return false;
            }
            uint32_t diff = 0;
            if (!json_parse_uint32(params, &diff)) {
                free(method);
                return false;
            }
            message->new_difficulty = diff;
            free(method);
            return true;
        }
        if (strcmp("mining.set_version_mask", method) == 0) {
            message->method = MINING_SET_VERSION_MASK;
            const char *params = json_find_key(stratum_json, "params");
            if (!params) {
                free(method);
                return false;
            }
            params = json_expect_char(params, '[');
            if (!params) {
                free(method);
                return false;
            }
            uint32_t version_mask = 0;
            if (!json_parse_hex_u32_from_string(params, &version_mask)) {
                free(method);
                return false;
            }
            message->version_mask = version_mask;
            free(method);
            return true;
        }
        if (strcmp("mining.set_extranonce", method) == 0) {
            message->method = MINING_SET_EXTRANONCE;
            const char *params = json_find_key(stratum_json, "params");
            if (!params) {
                free(method);
                return false;
            }
            params = json_expect_char(params, '[');
            if (!params) {
                free(method);
                return false;
            }
            char *extranonce = NULL;
            params = json_parse_string_dup(params, &extranonce);
            if (!params) {
                free(method);
                return false;
            }
            params = json_expect_char(params, ',');
            if (!params) {
                free(extranonce);
                free(method);
                return false;
            }
            int extranonce_len = 0;
            if (!json_parse_int(params, &extranonce_len)) {
                free(extranonce);
                free(method);
                return false;
            }
            if (extranonce_len > MAX_EXTRANONCE_2_LEN) {
                ESP_LOGW(TAG, "Extranonce_2_len %d exceeds maximum %d, clamping to maximum",
                         extranonce_len, MAX_EXTRANONCE_2_LEN);
                extranonce_len = MAX_EXTRANONCE_2_LEN;
            }
            message->extranonce_str = extranonce;
            message->extranonce_2_len = extranonce_len;
            free(method);
            return true;
        }
        if (strcmp("mining.ping", method) == 0) {
            message->method = MINING_PING;
            free(method);
            return true;
        }
        if (strcmp("client.reconnect", method) == 0) {
            message->method = CLIENT_RECONNECT;
            free(method);
            return true;
        }
        free(method);
        return false;
    }

    return parse_result_fast(message, stratum_json, parsed_id);
}

esp_transport_handle_t STRATUM_V1_transport_init(tls_mode tls, char * cert)
{
    esp_transport_handle_t transport;
    // tls_transport
    if (tls == DISABLED)
    {
        // tcp_transport
        ESP_LOGI(TAG, "TLS disabled, Using TCP transport");
        transport = esp_transport_tcp_init();
    }
    else{
        // tls_transport
        ESP_LOGI(TAG, "Using TLS transport");
        transport = esp_transport_ssl_init();
        if (transport == NULL) {
            ESP_LOGE(TAG, "Failed to initialize SSL transport");
            return NULL;
        }
        switch(tls){
            case BUNDLED_CRT:
                ESP_LOGI(TAG, "Using default cert bundle");
                esp_transport_ssl_crt_bundle_attach(transport, esp_crt_bundle_attach);
                break;
            case CUSTOM_CRT:
                ESP_LOGI(TAG, "Using custom cert");
                if (cert == NULL) {
                    ESP_LOGE(TAG, "Error: no TLS certificate");
                    return NULL;
                }
                esp_transport_ssl_set_cert_data(transport, cert, strlen(cert));
                break;
            default:
                ESP_LOGE(TAG, "Invalid TLS mode");
                esp_transport_destroy(transport);
                return NULL;
        }
    }
    return transport;
}

void STRATUM_V1_initialize_buffer()
{
    json_rpc_buffer = malloc(BUFFER_SIZE);
    json_rpc_buffer_size = BUFFER_SIZE;
    if (json_rpc_buffer == NULL) {
        printf("Error: Failed to allocate memory for buffer\n");
        exit(1);
    }
    memset(json_rpc_buffer, 0, BUFFER_SIZE);
}

void cleanup_stratum_buffer()
{
    free(json_rpc_buffer);
}

static void realloc_json_buffer(size_t len)
{
    size_t old, new;

    old = strlen(json_rpc_buffer);
    new = old + len + 1;

    if (new < json_rpc_buffer_size) {
        return;
    }

    new = new + (BUFFER_SIZE - (new % BUFFER_SIZE));
    void * new_sockbuf = realloc(json_rpc_buffer, new);

    if (new_sockbuf == NULL) {
        fprintf(stderr, "Error: realloc failed in recalloc_sock()\n");
        ESP_LOGI(TAG, "Restarting System because of ERROR: realloc failed in recalloc_sock");
        vTaskDelay(1000 / portTICK_PERIOD_MS);
        esp_restart();
    }

    json_rpc_buffer = new_sockbuf;
    memset(json_rpc_buffer + old, 0, new - old);
    json_rpc_buffer_size = new;
}

char * STRATUM_V1_receive_jsonrpc_line(esp_transport_handle_t transport)
{
    if (json_rpc_buffer == NULL) {
        STRATUM_V1_initialize_buffer();
    }
    char *line, *tok = NULL;
    char recv_buffer[BUFFER_SIZE];
    int nbytes;
    size_t buflen = 0;

    if (!strstr(json_rpc_buffer, "\n")) {
        do {
            memset(recv_buffer, 0, BUFFER_SIZE);
            nbytes = esp_transport_read(transport, recv_buffer, BUFFER_SIZE - 1, TRANSPORT_TIMEOUT_MS);
            if (nbytes < 0) {
                const char *err_str;
                switch(nbytes) {
                    case ERR_TCP_TRANSPORT_NO_MEM:
                        err_str = "No memory available";
                        break;
                    case ERR_TCP_TRANSPORT_CONNECTION_FAILED:
                        err_str = "Connection failed";
                        break;
                    case ERR_TCP_TRANSPORT_CONNECTION_CLOSED_BY_FIN:
                        err_str = "Connection closed by peer";
                        break;
                    default:
                        err_str = "Unknown error";
                        break;
                }
                ESP_LOGE(TAG, "Error: transport read failed: %s (code: %d)", err_str, nbytes);
                if (json_rpc_buffer) {
                    free(json_rpc_buffer);
                    json_rpc_buffer=0;
                }
                return 0;
            }

            realloc_json_buffer(nbytes);
            strncat(json_rpc_buffer, recv_buffer, nbytes);
        } while (!strstr(json_rpc_buffer, "\n"));
    }
    buflen = strlen(json_rpc_buffer);
    tok = strtok(json_rpc_buffer, "\n");
    line = strdup(tok);
    int len = strlen(line);
    if (buflen > len + 1)
        memmove(json_rpc_buffer, json_rpc_buffer + len + 1, buflen - len + 1);
    else
        strcpy(json_rpc_buffer, "");
    return line;
}

void STRATUM_V1_parse(StratumApiV1Message * message, const char * stratum_json)
{
    ESP_LOGI(TAG, "rx: %s", stratum_json); // debug incoming stratum messages
    if (STRATUM_V1_parse_fast(message, stratum_json)) {
        return;
    }

    cJSON * json = cJSON_Parse(stratum_json);

    cJSON * id_json = cJSON_GetObjectItem(json, "id");
    int parsed_id = -1;
    if (id_json != NULL && cJSON_IsNumber(id_json)) {
        parsed_id = id_json->valueint;
    }
    last_parsed_request_id = parsed_id;
    message->message_id = parsed_id;

    cJSON * method_json = cJSON_GetObjectItem(json, "method");
    stratum_method result = STRATUM_UNKNOWN;

    //if there is a method, then use that to decide what to do
    if (method_json != NULL && cJSON_IsString(method_json)) {
        if (strcmp("mining.notify", method_json->valuestring) == 0) {
            result = MINING_NOTIFY;
        } else if (strcmp("mining.set_difficulty", method_json->valuestring) == 0) {
            result = MINING_SET_DIFFICULTY;
        } else if (strcmp("mining.set_version_mask", method_json->valuestring) == 0) {
            result = MINING_SET_VERSION_MASK;
        } else if (strcmp("mining.set_extranonce", method_json->valuestring) == 0) {
            result = MINING_SET_EXTRANONCE;
        } else if (strcmp("client.reconnect", method_json->valuestring) == 0) {
            result = CLIENT_RECONNECT;
        } else if (strcmp("mining.ping", method_json->valuestring) == 0) {
            result = MINING_PING;
        } else {
            ESP_LOGI(TAG, "unhandled method in stratum message: %s", stratum_json);
        }

    //if there is no method, then it is a result
    } else {
        // parse results
        cJSON * result_json = cJSON_GetObjectItem(json, "result");
        cJSON * error_json = cJSON_GetObjectItem(json, "error");
        cJSON * reject_reason_json = cJSON_GetObjectItem(json, "reject-reason");

        // if the result is null, then it's a fail
        if (result_json == NULL) {
            message->response_success = false;
            message->error_str = strdup("unknown");
            
        // if it's an error, then it's a fail
        } else if (error_json != NULL && !cJSON_IsNull(error_json)) {
            message->response_success = false;
            message->error_str = strdup("unknown");
            if (parsed_id < 5) {
                result = STRATUM_RESULT_SETUP;
            } else {
                result = STRATUM_RESULT;
            }
            if (cJSON_IsArray(error_json)) {
                int len = cJSON_GetArraySize(error_json);
                if (len >= 2) {
                    cJSON * error_msg = cJSON_GetArrayItem(error_json, 1);
                    if (cJSON_IsString(error_msg)) {
                        message->error_str = strdup(cJSON_GetStringValue(error_msg));
                    }
                }
            }

        // if the result is a boolean, then parse it
        } else if (cJSON_IsBool(result_json)) {
            if (parsed_id < 5) {
                result = STRATUM_RESULT_SETUP;
            } else {
                result = STRATUM_RESULT;
            }
            if (cJSON_IsTrue(result_json)) {
                message->response_success = true;
            } else {
                message->response_success = false;
                message->error_str = strdup("unknown");
                if (cJSON_IsString(reject_reason_json)) {
                    message->error_str = strdup(cJSON_GetStringValue(reject_reason_json));
                }                
            }
        
        //if the id is STRATUM_ID_SUBSCRIBE parse it
        } else if (parsed_id == STRATUM_ID_SUBSCRIBE) {
            result = STRATUM_RESULT_SUBSCRIBE;

            cJSON * extranonce2_len_json = cJSON_GetArrayItem(result_json, 2);
            if (extranonce2_len_json == NULL) {
                ESP_LOGE(TAG, "Unable to parse extranonce2_len: %s", result_json->valuestring);
                message->response_success = false;
                goto done;
            }
            int extranonce_2_len = extranonce2_len_json->valueint;
            if (extranonce_2_len > MAX_EXTRANONCE_2_LEN) {
                ESP_LOGW(TAG, "Extranonce_2_len %d exceeds maximum %d, clamping to maximum", 
                         extranonce_2_len, MAX_EXTRANONCE_2_LEN);
                extranonce_2_len = MAX_EXTRANONCE_2_LEN;
            }
            message->extranonce_2_len = extranonce_2_len;

            cJSON * extranonce_json = cJSON_GetArrayItem(result_json, 1);
            if (extranonce_json == NULL) {
                ESP_LOGE(TAG, "Unable parse extranonce: %s", result_json->valuestring);
                message->response_success = false;
                goto done;
            }
            message->extranonce_str = strdup(extranonce_json->valuestring);
            message->response_success = true;
        //if the id is STRATUM_ID_CONFIGURE parse it
        } else if (parsed_id == STRATUM_ID_CONFIGURE) {
            cJSON * mask = cJSON_GetObjectItem(result_json, "version-rolling.mask");
            if (mask != NULL) {
                result = STRATUM_RESULT_VERSION_MASK;
                message->version_mask = strtoul(mask->valuestring, NULL, 16);
            } else {
                ESP_LOGI(TAG, "error setting version mask: %s", stratum_json);
            }

        } else {
            ESP_LOGI(TAG, "unhandled result in stratum message: %s", stratum_json);
        }
    }

    message->method = result;

    if (message->method == MINING_NOTIFY) {

        mining_notify * new_work = malloc(sizeof(mining_notify));
        // new_work->difficulty = difficulty;
        cJSON * params = cJSON_GetObjectItem(json, "params");
        new_work->job_id = strdup(cJSON_GetArrayItem(params, 0)->valuestring);
        new_work->prev_block_hash = strdup(cJSON_GetArrayItem(params, 1)->valuestring);
        new_work->coinbase_1 = strdup(cJSON_GetArrayItem(params, 2)->valuestring);
        new_work->coinbase_2 = strdup(cJSON_GetArrayItem(params, 3)->valuestring);
        new_work->coinbase_1_bin_len = strlen(new_work->coinbase_1) / 2;
        new_work->coinbase_2_bin_len = strlen(new_work->coinbase_2) / 2;
        new_work->coinbase_1_bin = malloc(new_work->coinbase_1_bin_len);
        new_work->coinbase_2_bin = malloc(new_work->coinbase_2_bin_len);
        if (new_work->coinbase_1_bin != NULL) {
            hex2bin(new_work->coinbase_1, new_work->coinbase_1_bin, new_work->coinbase_1_bin_len);
        }
        if (new_work->coinbase_2_bin != NULL) {
            hex2bin(new_work->coinbase_2, new_work->coinbase_2_bin, new_work->coinbase_2_bin_len);
        }

        cJSON * merkle_branch = cJSON_GetArrayItem(params, 4);
        new_work->n_merkle_branches = cJSON_GetArraySize(merkle_branch);
        if (new_work->n_merkle_branches > MAX_MERKLE_BRANCHES) {
            printf("Too many Merkle branches.\n");
            abort();
        }
        new_work->merkle_branches = malloc(HASH_SIZE * new_work->n_merkle_branches);
        for (size_t i = 0; i < new_work->n_merkle_branches; i++) {
            hex2bin(cJSON_GetArrayItem(merkle_branch, i)->valuestring, new_work->merkle_branches + HASH_SIZE * i, HASH_SIZE);
        }

        new_work->version = strtoul(cJSON_GetArrayItem(params, 5)->valuestring, NULL, 16);
        new_work->target = strtoul(cJSON_GetArrayItem(params, 6)->valuestring, NULL, 16);
        new_work->ntime = strtoul(cJSON_GetArrayItem(params, 7)->valuestring, NULL, 16);

        // params can be varible length
        int paramsLength = cJSON_GetArraySize(params);
        int value = cJSON_IsTrue(cJSON_GetArrayItem(params, paramsLength - 1));
        new_work->clean_jobs = value;

        message->mining_notification = new_work;
    } else if (message->method == MINING_SET_DIFFICULTY) {
        cJSON * params = cJSON_GetObjectItem(json, "params");
        uint32_t difficulty = cJSON_GetArrayItem(params, 0)->valueint;
        message->new_difficulty = difficulty;
    } else if (message->method == MINING_SET_VERSION_MASK) {
        cJSON * params = cJSON_GetObjectItem(json, "params");
        uint32_t version_mask = strtoul(cJSON_GetArrayItem(params, 0)->valuestring, NULL, 16);
        message->version_mask = version_mask;
    } else if (message->method == MINING_SET_EXTRANONCE) {
        cJSON * params = cJSON_GetObjectItem(json, "params");
        char * extranonce_str = cJSON_GetArrayItem(params, 0)->valuestring;
        uint32_t extranonce_2_len = cJSON_GetArrayItem(params, 1)->valueint;
        if (extranonce_2_len > MAX_EXTRANONCE_2_LEN) {
            ESP_LOGW(TAG, "Extranonce_2_len %u exceeds maximum %d, clamping to maximum", 
                     extranonce_2_len, MAX_EXTRANONCE_2_LEN);
            extranonce_2_len = MAX_EXTRANONCE_2_LEN;
        }
        message->extranonce_str = strdup(extranonce_str);
        message->extranonce_2_len = extranonce_2_len;
    }
    done:
    cJSON_Delete(json);
}

void STRATUM_V1_free_mining_notify(mining_notify * params)
{
    free(params->job_id);
    free(params->prev_block_hash);
    free(params->coinbase_1);
    free(params->coinbase_2);
    free(params->coinbase_1_bin);
    free(params->coinbase_2_bin);
    free(params->merkle_branches);
    free(params);
}

int _parse_stratum_subscribe_result_message(const char * result_json_str, char ** extranonce, int * extranonce2_len)
{
    cJSON * root = cJSON_Parse(result_json_str);
    if (root == NULL) {
        ESP_LOGE(TAG, "Unable to parse %s", result_json_str);
        return -1;
    }
    cJSON * result = cJSON_GetObjectItem(root, "result");
    if (result == NULL) {
        ESP_LOGE(TAG, "Unable to parse subscribe result %s", result_json_str);
        return -1;
    }

    cJSON * extranonce2_len_json = cJSON_GetArrayItem(result, 2);
    if (extranonce2_len_json == NULL) {
        ESP_LOGE(TAG, "Unable to parse extranonce2_len: %s", result->valuestring);
        return -1;
    }
    *extranonce2_len = extranonce2_len_json->valueint;

    cJSON * extranonce_json = cJSON_GetArrayItem(result, 1);
    if (extranonce_json == NULL) {
        ESP_LOGE(TAG, "Unable parse extranonce: %s", result->valuestring);
        return -1;
    }
    *extranonce = strdup(extranonce_json->valuestring);

    cJSON_Delete(root);

    return 0;
}

int STRATUM_V1_subscribe(esp_transport_handle_t transport, int send_uid, const char * model)
{
    // Subscribe
    const esp_app_desc_t *app_desc = esp_app_get_description();
    const char *version = app_desc->version;	
    return stratum_sendf(transport,
        "{\"id\":%d,\"method\":\"mining.subscribe\",\"params\":[\"bitaxe/%s/%s\"]}\n",
        send_uid, model, version);
}

int STRATUM_V1_suggest_difficulty(esp_transport_handle_t transport, int send_uid, uint32_t difficulty)
{
    return stratum_sendf(transport,
        "{\"id\":%d,\"method\":\"mining.suggest_difficulty\",\"params\":[%ld]}\n",
        send_uid, difficulty);
}

int STRATUM_V1_extranonce_subscribe(esp_transport_handle_t transport, int send_uid)
{
    return stratum_sendf(transport,
        "{\"id\":%d,\"method\":\"mining.extranonce.subscribe\",\"params\":[]}\n",
        send_uid);
}

int STRATUM_V1_authorize(esp_transport_handle_t transport, int send_uid, const char * username, const char * pass)
{
    return stratum_sendf(transport,
        "{\"id\":%d,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}\n",
        send_uid, username, pass);
}

int STRATUM_V1_pong(esp_transport_handle_t transport, int message_id)
{
    return stratum_sendf(transport,
        "{\"id\":%d,\"method\":\"pong\",\"params\":[]}\n",
        message_id);
}

/// @param transport Transport to write to
/// @param send_uid Message ID
/// @param username The client’s user name.
/// @param job_id The job ID for the work being submitted.
/// @param extranonce_2 The hex-encoded value of extra nonce 2.
/// @param ntime The hex-encoded time value use in the block header.
/// @param nonce The hex-encoded nonce value to use in the block header.
/// @param version_bits The hex-encoded version bits set by miner (BIP310).
int STRATUM_V1_submit_share(esp_transport_handle_t transport, int send_uid, const char * username, const char * job_id,
                            const char * extranonce_2, const uint32_t ntime,
                            const uint32_t nonce, const uint32_t version_bits)
{
    return stratum_sendf(transport,
        "{\"id\":%d,\"method\":\"mining.submit\",\"params\":[\"%s\",\"%s\",\"%s\",\"%08lx\",\"%08lx\",\"%08lx\"]}\n",
        send_uid, username, job_id, extranonce_2, ntime, nonce, version_bits);
}

int STRATUM_V1_configure_version_rolling(esp_transport_handle_t transport, int send_uid, uint32_t * version_mask)
{
    return stratum_sendf(transport,
        "{\"id\":%d,\"method\":\"mining.configure\",\"params\":[[\"version-rolling\"],{\"version-rolling.mask\":\"ffffffff\"}]}\n",
        send_uid);
}

static void debug_stratum_tx(const char * msg)
{
    STRATUM_V1_stamp_tx(last_parsed_request_id);
    //remove the trailing newline
    char * newline = strchr(msg, '\n');
    if (newline != NULL) {
        *newline = '\0';
    }
    ESP_LOGI(TAG, "tx: %s", msg);

    //put it back!
    if (newline != NULL) {
        *newline = '\n';
    }
}
