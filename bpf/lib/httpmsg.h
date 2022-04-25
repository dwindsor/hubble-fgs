#ifndef _HTTPMSG__
#define _HTTPMSG__

/* For HTTP users of msg_tls_ipv4 we set remaining field
 * to the direction. Either sender (HTTP_SEND) or receiver
 * (HTTP_RECV).
 */
#define HTTP_SEND 0
#define HTTP_RECV 1

#endif
