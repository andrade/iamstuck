#include <sgx_trts.h>
#include "enclave_t.h"

#include "chain_verify.h"

int make_ecall()
{
	printf("called make_ecall(), now inside the enclave\n");

	int r;

	r = validate_cert_chain();
	printf("validate_cert_chain, r = %d\n", r);

	r = verify_signature();
	printf("verify_signature, r = %d\n", r);

	return 0;
}

////////////////////////////////////////////////////////////////////////

// begin From WolfSSL

void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

int sprintf(char* buf, const char *fmt, ...)
{
	va_list ap;
	int ret;
	va_start(ap, fmt);
	ret = vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	return ret;
}

double current_time(void)
{
	double curr;
	ocall_current_time(&curr);
	return curr;
}

int LowResTimer(void) /* low_res timer */
{
	int time;
	ocall_low_res_time(&time);
	return time;
}

size_t recv(int sockfd, void *buf, size_t len, int flags)
{
	size_t ret;
	int sgxStatus;
	sgxStatus = ocall_recv(&ret, sockfd, buf, len, flags);
	return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
	size_t ret;
	int sgxStatus;
	sgxStatus = ocall_send(&ret, sockfd, buf, len, flags);
	return ret;
}

// end From WolfSSL
