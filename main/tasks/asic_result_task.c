#include <lwip/tcpip.h>

#include "system.h"
#include "work_queue.h"
#include "serial.h"
#include <string.h>
#include "esp_log.h"
#include "nvs_config.h"
#include "utils.h"
#include "stratum_task.h"
#include "hashrate_monitor_task.h"
#include "asic.h"

static const char *TAG = "asic_result";
#define JOBID_MAX_LEN 128
#define EXTRANONCE2_MAX_LEN (2 * 32 + 1) // MAX_EXTRANONCE_2_LEN * 2 + NUL

void ASIC_result_task(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    while (1)
    {
        // Check if ASIC is initialized before trying to process work
        if (!GLOBAL_STATE->ASIC_initalized) {
            vTaskDelay(100 / portTICK_PERIOD_MS);
            continue;
        }
        
        //task_result *asic_result = (*GLOBAL_STATE->ASIC_functions.receive_result_fn)(GLOBAL_STATE);
        task_result *asic_result = ASIC_process_work(GLOBAL_STATE);

        if (asic_result == NULL)
        {
            continue;
        }

        if (asic_result->register_type != REGISTER_INVALID) {
            hashrate_monitor_register_read(GLOBAL_STATE, asic_result->register_type, asic_result->asic_nr, asic_result->value);
            continue;
        }

        uint8_t job_id = asic_result->job_id;

        bm_job job_snapshot = {0};
        char jobid_copy[JOBID_MAX_LEN];
        char extranonce2_copy[EXTRANONCE2_MAX_LEN];
        uint32_t pool_diff = 0;
        uint32_t job_version = 0;
        uint32_t job_ntime = 0;
        bool have_jobid = false;
        bool have_extranonce2 = false;

        memset(jobid_copy, 0, sizeof(jobid_copy));
        memset(extranonce2_copy, 0, sizeof(extranonce2_copy));

        pthread_mutex_lock(&GLOBAL_STATE->valid_jobs_lock);
        if (GLOBAL_STATE->valid_jobs[job_id] == 0 || GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id] == NULL)
        {
            pthread_mutex_unlock(&GLOBAL_STATE->valid_jobs_lock);
            ESP_LOGW(TAG, "Invalid job nonce found, 0x%02X", job_id);
            continue;
        }

        bm_job *active_job = GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[job_id];
        job_snapshot = *active_job;
        pool_diff = active_job->pool_diff;
        job_version = active_job->version;
        job_ntime = active_job->ntime;

        if (active_job->jobid != NULL) {
            size_t jobid_len = strnlen(active_job->jobid, JOBID_MAX_LEN);
            if (jobid_len < JOBID_MAX_LEN) {
                memcpy(jobid_copy, active_job->jobid, jobid_len);
                jobid_copy[jobid_len] = '\0';
                have_jobid = true;
            } else {
                ESP_LOGW(TAG, "Job ID too long, skipping submit");
            }
        }
        if (active_job->extranonce2 != NULL) {
            size_t ex2_len = strnlen(active_job->extranonce2, EXTRANONCE2_MAX_LEN);
            if (ex2_len < EXTRANONCE2_MAX_LEN) {
                memcpy(extranonce2_copy, active_job->extranonce2, ex2_len);
                extranonce2_copy[ex2_len] = '\0';
                have_extranonce2 = true;
            } else {
                ESP_LOGW(TAG, "Extranonce2 too long, skipping submit");
            }
        }

        pthread_mutex_unlock(&GLOBAL_STATE->valid_jobs_lock);

        // check the nonce difficulty without holding the job lock
        double nonce_diff = test_nonce_value(&job_snapshot, asic_result->nonce, asic_result->rolled_version);

        //log the ASIC response
        ESP_LOGD(TAG, "ID: %s, ASIC nr: %d, ver: %08" PRIX32 " Nonce %08" PRIX32 " diff %.1f of %ld.",
                 have_jobid ? jobid_copy : "(null)", asic_result->asic_nr, asic_result->rolled_version,
                 asic_result->nonce, nonce_diff, pool_diff);

        SYSTEM_notify_found_nonce(GLOBAL_STATE, nonce_diff, job_id);

        if (nonce_diff >= pool_diff && have_jobid && have_extranonce2)
        {
            char * user = GLOBAL_STATE->SYSTEM_MODULE.is_using_fallback ? GLOBAL_STATE->SYSTEM_MODULE.fallback_pool_user : GLOBAL_STATE->SYSTEM_MODULE.pool_user;
            int ret = STRATUM_V1_submit_share(
                GLOBAL_STATE->transport,
                GLOBAL_STATE->send_uid++,
                user,
                jobid_copy,
                extranonce2_copy,
                job_ntime,
                asic_result->nonce,
                asic_result->rolled_version ^ job_version);

            if (ret < 0) {
                ESP_LOGI(TAG, "Unable to write share to socket. Closing connection. Ret: %d (errno %d: %s)", ret, errno, strerror(errno));
                stratum_close_connection(GLOBAL_STATE);
            }
        }

    }
}
