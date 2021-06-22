// get socket cookie helper
__u64 get_cookie(struct sock *skp) {
	__u64 cookie = 0;
	probe_read(&cookie, sizeof(cookie), _(&(skp->__sk_common.skc_cookie)));
	return cookie;
}
