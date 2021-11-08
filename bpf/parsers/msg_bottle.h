#ifndef msg_bottle_h_INCLUDED
#define msg_bottle_h_INCLUDED

#ifdef SK_MSG
#define msg_bottle sk_msg_md

static inline __attribute__((always_inline))
void *msg_bottle_get_data(struct sk_msg_md *msg, int off, int len)
{
	void *data = msg->data + off;

	if (data + len > msg->data_end) {
		int err = msg_pull_data(msg, 0, off + len, 0);
		if (err < 0) {
			msg_cork_bytes(msg, off + len);
			return 0;
		}

		data = msg->data + off;

		if (data + len > msg->data_end)
			return 0;
	}

	return data;
}

#else
#include "skb_bottle.h"

#define msg_bottle skb_bottle
#define msg_bottle_get_data skb_bottle_get_data
#endif

#endif // msg_bottle_h_INCLUDED

