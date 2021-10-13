#ifndef __SOCK_H__
#define __SOCK_H__

struct sk_type {
	__u16 family;
	__u16 type;
	__u16 protocol;
	__u16 pad;
	__u32 mark;
	__u32 priority;
};

/* set_event_from_sock(sock)
 *
 * Populate the event args with the sock info.
 */
static inline __attribute__((unused))
void set_event_from_sock(struct sk_type *event, struct sock *sk)
{
	struct sock_common *common = (struct sock_common *)sk;

	event->family = 0;
	probe_read(&event->family, sizeof(event->family), _(&common->skc_family));
	probe_read(&event->type, sizeof(event->type), _(&sk->sk_type));
	probe_read(&event->protocol, sizeof(event->protocol), _(&sk->sk_protocol));
	probe_read(&event->mark, sizeof(event->mark), _(&sk->sk_mark));
	probe_read(&event->priority, sizeof(event->priority), _(&sk->sk_priority));
}
#endif // __SOCK_H__
