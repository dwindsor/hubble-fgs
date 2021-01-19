/* Type IDs form API with user space generickprobe.go */
enum {
	string_type = 1,
	int_type = 2,
	skb_type = 3,
	size_type = 4,
};

struct skb_type {
	__u32 hash;
	__u32 len;
	__u32 priority;
	__u32 mark;
};

/* Constansts bounding printers if these change or buffer size changes then
 * we will need to resize. TBD would be to size these at compile time using
 * buffer size information.
 */
#define MAX_STRING 1024

static inline __attribute__((always_inline))
int read_call_arg(char *args, int type, long off, unsigned long arg)
{
	int size = -1;

	if (type == string_type && MAX_STRING + off < 4095) {
		int *s = (int *)&args[off];

		size = probe_read_str(&args[off+4], MAX_STRING, (char *)arg);
		*s = size;
	} else if (type == size_type && sizeof(size_t) + off < 4095) {
		probe_read(&args[off], sizeof(size_t), &arg);
		size = sizeof(size_t);
	} else if (type == int_type && sizeof(int) + off < 4095) {
		size  = sizeof(int);
		probe_read(&args[off], size, &arg);
	} else if (type == skb_type && sizeof(struct skb_type) + off < 4095) {
		struct sk_buff *skb = (struct sk_buff *)arg;
		struct skb_type *skb_event = (struct skb_type *)&args[off];

		probe_read(&skb_event->hash, sizeof(__u32), _(&skb->hash));
		probe_read(&skb_event->len, sizeof(__u32), _(&skb->len));
		probe_read(&skb_event->priority, sizeof(__u32), _(&skb->priority));
		probe_read(&skb_event->mark, sizeof(__u32), _(&skb->mark));
		size = sizeof(struct skb_type);
	}
	return size;
}
