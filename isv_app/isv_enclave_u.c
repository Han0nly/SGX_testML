#include "isv_enclave_u.h"
#include <errno.h>

typedef struct ms_ECALL_enclave_DO_config_t {
	sgx_status_t ms_retval;
	int ms_num_DOs;
} ms_ECALL_enclave_DO_config_t;

typedef struct ms_ECALL_test_enclave_t {
	sgx_status_t ms_retval;
} ms_ECALL_test_enclave_t;

typedef struct ms_ECALL_enclave_init_ra_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_p_context;
} ms_ECALL_enclave_init_ra_t;

typedef struct ms_ECALL_enclave_ra_close_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
} ms_ECALL_enclave_ra_close_t;

typedef struct ms_ECALL_verify_att_result_mac_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_message;
	size_t ms_message_size;
	uint8_t* ms_mac;
	size_t ms_mac_size;
} ms_ECALL_verify_att_result_mac_t;

typedef struct ms_ECALL_put_secret_data_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_p_secret;
	uint32_t ms_secret_size;
	uint8_t* ms_p_gcm_mac;
	uint32_t ms_provisioner_type;
} ms_ECALL_put_secret_data_t;

typedef struct ms_ECALL_compute_task1_single_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_p_data_encrypted;
	uint32_t ms_data_size;
	uint8_t* ms_p_data_gcm_mac;
	uint8_t* ms_p_result_encrypted;
	uint32_t ms_result_size;
	uint8_t* ms_p_result_gcm_mac;
	uint8_t* ms_p_rand_key_DC_encrypted;
	uint8_t* ms_p_rand_key_DC_mac;
} ms_ECALL_compute_task1_single_t;

typedef struct ms_ECALL_compute_task1_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_data_num;
	uint32_t* ms_dataSizes;
	uint32_t* ms_macSizes;
	uint8_t* ms_p_data_encrypted;
	uint32_t ms_data_size;
	uint8_t* ms_p_data_gcm_mac;
	uint32_t ms_mac_size;
	uint8_t* ms_p_result_encrypted;
	uint32_t ms_result_size;
	uint8_t* ms_p_result_gcm_mac;
} ms_ECALL_compute_task1_t;

typedef struct ms_ECALL_compute_task2_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_data_num;
	uint32_t* ms_dataSizes;
	uint32_t* ms_macSizes;
	uint8_t* ms_p_data_encrypted;
	uint32_t ms_data_size;
	uint8_t* ms_p_data_gcm_mac;
	uint32_t ms_mac_size;
	uint8_t* ms_p_result_encrypted;
	uint32_t ms_result_size;
	uint8_t* ms_p_result_gcm_mac;
} ms_ECALL_compute_task2_t;

typedef struct ms_ECALL_compute_task3_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_data_num;
	uint32_t* ms_dataSizes;
	uint32_t* ms_macSizes;
	uint8_t* ms_p_data_encrypted;
	uint32_t ms_data_size;
	uint8_t* ms_p_data_gcm_mac;
	uint32_t ms_mac_size;
	uint8_t* ms_p_result_encrypted;
	uint32_t ms_result_size;
	uint8_t* ms_p_result_gcm_mac;
} ms_ECALL_compute_task3_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const sgx_ra_msg2_t* ms_p_msg2;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_OCALL_print_string_t {
	const char* ms_str;
} ms_OCALL_print_string_t;

static sgx_status_t SGX_CDECL isv_enclave_OCALL_print_string(void* pms)
{
	ms_OCALL_print_string_t* ms = SGX_CAST(ms_OCALL_print_string_t*, pms);
	OCALL_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_isv_enclave = {
	1,
	{
		(void*)isv_enclave_OCALL_print_string,
	}
};
sgx_status_t ECALL_enclave_DO_config(sgx_enclave_id_t eid, sgx_status_t* retval, int num_DOs)
{
	sgx_status_t status;
	ms_ECALL_enclave_DO_config_t ms;
	ms.ms_num_DOs = num_DOs;
	status = sgx_ecall(eid, 0, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ECALL_test_enclave(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_ECALL_test_enclave_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ECALL_enclave_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context)
{
	sgx_status_t status;
	ms_ECALL_enclave_init_ra_t ms;
	ms.ms_b_pse = b_pse;
	ms.ms_p_context = p_context;
	status = sgx_ecall(eid, 2, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ECALL_enclave_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context)
{
	sgx_status_t status;
	ms_ECALL_enclave_ra_close_t ms;
	ms.ms_context = context;
	status = sgx_ecall(eid, 3, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ECALL_verify_att_result_mac(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size)
{
	sgx_status_t status;
	ms_ECALL_verify_att_result_mac_t ms;
	ms.ms_context = context;
	ms.ms_message = message;
	ms.ms_message_size = message_size;
	ms.ms_mac = mac;
	ms.ms_mac_size = mac_size;
	status = sgx_ecall(eid, 4, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ECALL_put_secret_data(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* p_gcm_mac, uint32_t provisioner_type)
{
	sgx_status_t status;
	ms_ECALL_put_secret_data_t ms;
	ms.ms_context = context;
	ms.ms_p_secret = p_secret;
	ms.ms_secret_size = secret_size;
	ms.ms_p_gcm_mac = p_gcm_mac;
	ms.ms_provisioner_type = provisioner_type;
	status = sgx_ecall(eid, 5, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ECALL_compute_task1_single(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* p_data_encrypted, uint32_t data_size, uint8_t* p_data_gcm_mac, uint8_t* p_result_encrypted, uint32_t result_size, uint8_t* p_result_gcm_mac, uint8_t* p_rand_key_DC_encrypted, uint8_t* p_rand_key_DC_mac)
{
	sgx_status_t status;
	ms_ECALL_compute_task1_single_t ms;
	ms.ms_context = context;
	ms.ms_p_data_encrypted = p_data_encrypted;
	ms.ms_data_size = data_size;
	ms.ms_p_data_gcm_mac = p_data_gcm_mac;
	ms.ms_p_result_encrypted = p_result_encrypted;
	ms.ms_result_size = result_size;
	ms.ms_p_result_gcm_mac = p_result_gcm_mac;
	ms.ms_p_rand_key_DC_encrypted = p_rand_key_DC_encrypted;
	ms.ms_p_rand_key_DC_mac = p_rand_key_DC_mac;
	status = sgx_ecall(eid, 6, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ECALL_compute_task1(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t data_num, uint32_t* dataSizes, uint32_t* macSizes, uint8_t* p_data_encrypted, uint32_t data_size, uint8_t* p_data_gcm_mac, uint32_t mac_size, uint8_t* p_result_encrypted, uint32_t result_size, uint8_t* p_result_gcm_mac)
{
	sgx_status_t status;
	ms_ECALL_compute_task1_t ms;
	ms.ms_context = context;
	ms.ms_data_num = data_num;
	ms.ms_dataSizes = dataSizes;
	ms.ms_macSizes = macSizes;
	ms.ms_p_data_encrypted = p_data_encrypted;
	ms.ms_data_size = data_size;
	ms.ms_p_data_gcm_mac = p_data_gcm_mac;
	ms.ms_mac_size = mac_size;
	ms.ms_p_result_encrypted = p_result_encrypted;
	ms.ms_result_size = result_size;
	ms.ms_p_result_gcm_mac = p_result_gcm_mac;
	status = sgx_ecall(eid, 7, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ECALL_compute_task2(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t data_num, uint32_t* dataSizes, uint32_t* macSizes, uint8_t* p_data_encrypted, uint32_t data_size, uint8_t* p_data_gcm_mac, uint32_t mac_size, uint8_t* p_result_encrypted, uint32_t result_size, uint8_t* p_result_gcm_mac)
{
	sgx_status_t status;
	ms_ECALL_compute_task2_t ms;
	ms.ms_context = context;
	ms.ms_data_num = data_num;
	ms.ms_dataSizes = dataSizes;
	ms.ms_macSizes = macSizes;
	ms.ms_p_data_encrypted = p_data_encrypted;
	ms.ms_data_size = data_size;
	ms.ms_p_data_gcm_mac = p_data_gcm_mac;
	ms.ms_mac_size = mac_size;
	ms.ms_p_result_encrypted = p_result_encrypted;
	ms.ms_result_size = result_size;
	ms.ms_p_result_gcm_mac = p_result_gcm_mac;
	status = sgx_ecall(eid, 8, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ECALL_compute_task3(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t data_num, uint32_t* dataSizes, uint32_t* macSizes, uint8_t* p_data_encrypted, uint32_t data_size, uint8_t* p_data_gcm_mac, uint32_t mac_size, uint8_t* p_result_encrypted, uint32_t result_size, uint8_t* p_result_gcm_mac)
{
	sgx_status_t status;
	ms_ECALL_compute_task3_t ms;
	ms.ms_context = context;
	ms.ms_data_num = data_num;
	ms.ms_dataSizes = dataSizes;
	ms.ms_macSizes = macSizes;
	ms.ms_p_data_encrypted = p_data_encrypted;
	ms.ms_data_size = data_size;
	ms.ms_p_data_gcm_mac = p_data_gcm_mac;
	ms.ms_mac_size = mac_size;
	ms.ms_p_result_encrypted = p_result_encrypted;
	ms.ms_result_size = result_size;
	ms.ms_p_result_gcm_mac = p_result_gcm_mac;
	status = sgx_ecall(eid, 9, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 10, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = p_msg2;
	ms.ms_p_qe_target = p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 11, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 12, &ocall_table_isv_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

