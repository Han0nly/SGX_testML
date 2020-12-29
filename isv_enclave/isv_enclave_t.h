#ifndef ISV_ENCLAVE_T_H__
#define ISV_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_key_exchange.h"
#include "sgx_trts.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ECALL_enclave_DO_config(int num_DOs);
sgx_status_t ECALL_test_enclave(void);
sgx_status_t ECALL_enclave_init_ra(int b_pse, sgx_ra_context_t* p_context);
sgx_status_t ECALL_enclave_ra_close(sgx_ra_context_t context);
sgx_status_t ECALL_verify_att_result_mac(sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
sgx_status_t ECALL_put_secret_data(sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* p_gcm_mac, uint32_t provisioner_type);
sgx_status_t ECALL_compute_task1_single(sgx_ra_context_t context, uint8_t* p_data_encrypted, uint32_t data_size, uint8_t* p_data_gcm_mac, uint8_t* p_result_encrypted, uint32_t result_size, uint8_t* p_result_gcm_mac, uint8_t* p_rand_key_DC_encrypted, uint8_t* p_rand_key_DC_mac);
sgx_status_t ECALL_compute_task1(sgx_ra_context_t context, uint32_t data_num, uint32_t* dataSizes, uint32_t* macSizes, uint8_t* p_data_encrypted, uint32_t data_size, uint8_t* p_data_gcm_mac, uint32_t mac_size, uint8_t* p_result_encrypted, uint32_t result_size, uint8_t* p_result_gcm_mac);
sgx_status_t ECALL_compute_task2(sgx_ra_context_t context, uint32_t data_num, uint32_t* dataSizes, uint32_t* macSizes, uint8_t* p_data_encrypted, uint32_t data_size, uint8_t* p_data_gcm_mac, uint32_t mac_size, uint8_t* p_result_encrypted, uint32_t result_size, uint8_t* p_result_gcm_mac);
sgx_status_t ECALL_compute_task3(sgx_ra_context_t context, uint32_t data_num, uint32_t* dataSizes, uint32_t* macSizes, uint8_t* p_data_encrypted, uint32_t data_size, uint8_t* p_data_gcm_mac, uint32_t mac_size, uint8_t* p_result_encrypted, uint32_t result_size, uint8_t* p_result_gcm_mac);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

sgx_status_t SGX_CDECL OCALL_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif