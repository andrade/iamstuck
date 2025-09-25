// #define _POSIX_C_SOURCE 201710L
// #define WOLFSSL_USE_OPTIONS_H

#include <assert.h>
#include <stdio.h>

////////////////////////////////////////////////////////////////////////

#include <sgx_urts.h>
#include "enclave_u.h"

#ifndef SGX_ENCLAVE_PATH
#define SGX_ENCLAVE_PATH "enclave.signed.so"
#endif

// create a new enclave instance
static int enclave_ping(sgx_enclave_id_t *enclave_id)
{
	sgx_status_t ss = SGX_ERROR_UNEXPECTED;

	ss = sgx_create_enclave(SGX_ENCLAVE_PATH, SGX_DEBUG_FLAG, NULL, NULL, enclave_id, NULL);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "sgx_create_enclave: 0x%04x\n", ss);
		return 1;
	}
	fprintf(stderr, "sgx_create_enclave: 0x%04x\n", ss);

	return 0;
}

// destroy an existing enclave instance
static int enclave_pong(sgx_enclave_id_t *enclave_id)
{
	sgx_status_t ss = SGX_ERROR_UNEXPECTED;

	ss = sgx_destroy_enclave(*enclave_id);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "sgx_destroy_enclave: 0x%04x\n", ss);
		return 1;
	}
	fprintf(stderr, "sgx_destroy_enclave: 0x%04x\n", ss);

	return 0;
}

////////////////////////////////////////////////////////////////////////

int main(void)
{
	sgx_enclave_id_t eid;
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	int result = -1;

	if (enclave_ping(&eid)) {
		return EXIT_FAILURE;
	}


	status = make_ecall(eid, &result);
	if (SGX_SUCCESS != status) {
		fprintf(stderr, "make_ecall, status: 0x%04x\n", status);
		return EXIT_FAILURE;
	}
	printf("make_ecall, result = %d\n", result);


	if (enclave_pong(&eid)) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
