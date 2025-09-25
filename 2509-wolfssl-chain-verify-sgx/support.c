/**
** Implements the untrusted functions of the interface.
**/

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include <sys/types.h> /* for send/recv */
#include <sys/socket.h> /* for send/recv */

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

#include <sgx_urts.h>
#include "enclave_u.h"

// void dump_str(const char *str)
// {
// 	printf("print_u: %s\n", str);
// }

////////////////////////////////////////////////////////////////////////

// begin From WolfSSL

static double current_time()
{
	struct timeval tv;
	gettimeofday(&tv,NULL);

	return (double)(1000000 * tv.tv_sec + tv.tv_usec)/1000000.0;
}

void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
	 * the input string to prevent buffer overflow.
	 */ printf("%s", str);
}

void ocall_current_time(double* time)
{
	if(!time) return;
	*time = current_time();
	return;
}

void ocall_low_res_time(int* time)
{
	struct timeval tv;
	if(!time) return;
	*time = tv.tv_sec;
	return;
}

size_t ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
	return recv(sockfd, buf, len, flags);
}

size_t ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
	return send(sockfd, buf, len, flags);
}

// end From WolfSSL
