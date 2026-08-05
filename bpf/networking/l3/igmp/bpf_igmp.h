// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#include "vmlinux.h"
#include "api.h"
#include "bpf_event.h"
#include "bpf_cookie.h"
#include "bpf_network_helpers.h"
#include "fgs_rodata_config.h"

// Copied from /include/uapi/linux/igmp.h
#define IGMP_HOST_MEMBERSHIP_REPORT   0x12
#define IGMPV2_HOST_MEMBERSHIP_REPORT 0x16
#define IGMP_HOST_LEAVE_MESSAGE	      0x17
#define IGMPV3_HOST_MEMBERSHIP_REPORT 0x22
#define IGMPV3_MODE_IS_INCLUDE	      1
#define IGMPV3_MODE_IS_EXCLUDE	      2

#define IGMPV3_REPORT_ADDRESS 0x160000E0 // 224.0.0.22 as LSB u32
#define IGMP_ALL_HOSTS	      0x010000E0 // 224.0.0.1 as LSB u32

static inline __attribute__((always_inline)) int
ip_mc_join_group(void *ctx, u64 cookie, struct ip_mreqn *imr, unsigned int mode)
{
	struct msg_process_igmp_join_event *event;
	struct socketmap_value *process;
	int zero = 0;

	event = (struct msg_process_igmp_join_event *)map_lookup_elem(&tg_h_event, &zero);
	if (!event)
		return 0;

	process = lookup_socketmap(&cookie);
	if (!process) {
		emit_ip_error_event(ctx, 0, &cookie, false, 0, 2, 0, IP_ERROR_IGMP_JOIN_MISSING_PROCESS);
		return 0;
	}

	event->common.op = ISO_MSG_OP_IGMP_JOIN;
	event->common.ktime = tg_get_ktime();
	event->common.size = sizeof(struct msg_process_igmp_join_event);
	event->key = process->key;

	probe_read_kernel(&event->saddr, sizeof(event->saddr), _(&imr->imr_address));
	probe_read_kernel(&event->gaddr, sizeof(event->gaddr), _(&imr->imr_multiaddr));
	probe_read_kernel(&event->ifindex, sizeof(event->ifindex), _(&imr->imr_ifindex));

	event->socket_cookie = cookie;

	perf_event_output_metric(ctx, ISO_MSG_OP_IGMP_JOIN, &tcpmon_map, BPF_F_CURRENT_CPU, event,
				 sizeof(struct msg_process_igmp_join_event));
	return 0;
}

static inline __attribute__((always_inline)) int
ip_mc_leave_group(void *ctx, u64 cookie, struct ip_mreqn *imr)
{
	struct msg_process_igmp_leave_event *event;
	struct socketmap_value *process;
	int zero = 0;

	event = (struct msg_process_igmp_leave_event *)map_lookup_elem(&tg_h_event, &zero);
	if (!event)
		return 0;

	process = lookup_socketmap(&cookie);
	if (!process) {
		emit_ip_error_event(ctx, 0, &cookie, false, 0, 2, 0, IP_ERROR_IGMP_LEAVE_MISSING_PROCESS);
		return 0;
	}

	event->common.op = ISO_MSG_OP_IGMP_LEAVE;
	event->common.ktime = tg_get_ktime();
	event->common.size = sizeof(struct msg_process_igmp_leave_event);
	event->key = process->key;

	probe_read_kernel(&event->saddr, sizeof(event->saddr), _(&imr->imr_address));
	probe_read_kernel(&event->gaddr, sizeof(event->gaddr), _(&imr->imr_multiaddr));
	probe_read_kernel(&event->ifindex, sizeof(event->ifindex), _(&imr->imr_ifindex));

	event->socket_cookie = cookie;

	perf_event_output_metric(ctx, ISO_MSG_OP_IGMP_LEAVE, &tcpmon_map, BPF_F_CURRENT_CPU, event,
				 sizeof(struct msg_process_igmp_leave_event));
	return 0;
}

static inline __attribute__((always_inline)) int
igmp_send_report(void *ctx, struct in_device *in_dev, struct ip_mc_list *pmc, int type)
{
	struct msg_igmp_membership_report *event;
	struct net_device *dev;
	struct in_ifaddr *ifa;
	int zero = 0;

	// We only care about membership reports and leave messages.
	// We handle V3 membership reports here as if they were V2 and have no group
	// records. This is for kernels (<v6.6) where complexity issues prevent the group
	// record parsing.
	if (type != IGMP_HOST_MEMBERSHIP_REPORT &&
	    type != IGMPV2_HOST_MEMBERSHIP_REPORT &&
	    type != IGMPV3_HOST_MEMBERSHIP_REPORT &&
	    type != IGMP_HOST_LEAVE_MESSAGE)
		return 0;

	event = (struct msg_igmp_membership_report *)map_lookup_elem(&tg_h_event, &zero);
	if (!event)
		return 0;

	event->common.op = ISO_MSG_OP_IGMP_REPORT;
	event->common.ktime = tg_get_ktime();
	event->type = type;
	if (pmc)
		probe_read_kernel(&event->gaddr, sizeof(event->gaddr), _(&pmc->multiaddr));
	else if (type == IGMPV3_HOST_MEMBERSHIP_REPORT)
		// For V3 we only report that a membership report was sent, as there could
		// be multiple group records and reporting only the first could lead to
		// confusion. All users of IGMPV3 should run kernel v6.6 or later for a
		// far improved experience.
		event->gaddr = IGMPV3_REPORT_ADDRESS;
	else
		event->gaddr = 0;
	event->num_group_records = 0;
	probe_read_kernel(&dev, sizeof(dev), _(&in_dev->dev));
	if (dev) {
		probe_read_kernel(&event->ifindex, sizeof(event->ifindex), _(&dev->ifindex));
		probe_read_kernel(&event->ifname, sizeof(event->ifname), _(&dev->name));
	} else {
		event->ifindex = 0;
		event->ifname[0] = 0;
	}
	probe_read_kernel(&ifa, sizeof(ifa), _(&in_dev->ifa_list));
	if (ifa)
		probe_read_kernel(&event->saddr, sizeof(event->saddr), _(&ifa->ifa_address));
	else
		event->saddr = 0;

	event->common.size = sizeof(struct msg_igmp_membership_report);
	perf_event_output_metric(ctx, ISO_MSG_OP_IGMP_REPORT, &tcpmon_map, BPF_F_CURRENT_CPU, event,
				 sizeof(struct msg_igmp_membership_report));
	return 0;
}

// Adds a group record to a IGMPV3 report
__attribute__((noinline)) int
add_grec(u16 offset, u64 pmc_ptr, int type)
{
	// rec points to free space either after the membership report or after
	// the last group record. This is filled in with the current group record.
	// sources_ptr points to free space after the current group record. This
	// is filled with IPv4 source addresses.
	// We return -1 to indicate no record was added, or the number of sources
	// that were added.
	struct ip_mc_list *pmc = (struct ip_mc_list *)pmc_ptr;
	struct msg_igmp_group_record *rec;
	struct ip_sf_list *psf;
	u16 num_sources = 0;
	u32 *sources_ptr;
	int zero = 0;
	u32 gaddr;
	void *ptr;

	ptr = map_lookup_elem(&tg_h_event, &zero);
	if (!ptr)
		return -1;
	ptr += (offset & (MAX_EVENT_SIZE / 2 - 1));
	rec = (struct msg_igmp_group_record *)ptr;
	sources_ptr = (u32 *)(ptr + sizeof(struct msg_igmp_group_record));

	probe_read_kernel(&gaddr, sizeof(gaddr), _(&pmc->multiaddr));
	if (gaddr == IGMP_ALL_HOSTS)
		return -1;
	rec->type = type;
	rec->gaddr = gaddr;

	// We need to walk the source list. As per below, we will use a simple for
	// loop over a range and break when there are no more source addresses.
	probe_read_kernel(&psf, sizeof(psf), _(&pmc->sources));
	for (u16 i = 0; i < FGS_CONFIG(TG_IGMPV3_MAX_SOURCES); i++) {
		if (!psf)
			break;

		probe_read_kernel(sources_ptr, sizeof(*sources_ptr), _(&psf->sf_inaddr));
		sources_ptr++;
		num_sources++;

		probe_read_kernel(&psf, sizeof(psf), _(&psf->sf_next));
	}

	rec->num_sources = num_sources;
	return num_sources;
}

// Adds a PMC to a IGMPV3 report
__attribute__((noinline)) int
add_pmc(u16 offset, u64 pmc_ptr)
{
	struct ip_mc_list *pmc = (struct ip_mc_list *)pmc_ptr;
	unsigned long sfcount_mcast_exclude;
	int num_sources;
	u32 gaddr;
	int type;

	probe_read_kernel(&gaddr, sizeof(gaddr), _(&pmc->multiaddr));
	if (gaddr == IGMP_ALL_HOSTS)
		return 0;

	probe_read_kernel(&sfcount_mcast_exclude, sizeof(sfcount_mcast_exclude), _(&pmc->sfcount));
	if (sfcount_mcast_exclude)
		type = IGMPV3_MODE_IS_EXCLUDE;
	else
		type = IGMPV3_MODE_IS_INCLUDE;
	num_sources = add_grec(offset, pmc_ptr, type);
	if (num_sources < 0)
		return 0;
	return sizeof(struct msg_igmp_group_record) + (num_sources * sizeof(u32));
}

// Adds a list of PMCs to a IGMPV3 report. Returns when the event is full or when
// there are no more PMCs.
// We take a pointer to a pmc pointer as argument. This is so we can access the pmc
// that we need to start from, but also that as we traverse the list, our updated
// pmc_ptr is available to the caller.
__attribute__((noinline)) int
add_pmcs(u64 *pmc_ptr)
{
	int offset = sizeof(struct msg_igmp_membership_report);
	struct msg_igmp_membership_report *event;
	u16 num_gr = 0;
	int zero = 0;
	u16 gr_size;

	event = (struct msg_igmp_membership_report *)map_lookup_elem(&tg_h_event, &zero);
	if (!event || !pmc_ptr)
		return -1;

	// We need to replicate for_each_pmc_rcu(in_dev, pmc) but the verifier will struggle
	// to accept that the loop will end. Instead, we'll do a for loop over a set range
	// and exit the loop when there are no more IP lists, or our event is full.
	for (u16 i = 0; i < FGS_CONFIG(TG_IGMPV3_MAX_PMCS); i++) {
		if (!*pmc_ptr) {
			event->num_group_records = num_gr;
			event->common.size = offset & (MAX_EVENT_SIZE / 2 - 1);
			return event->common.size;
		}

		gr_size = add_pmc(offset, *pmc_ptr);
		if (gr_size > 0) {
			if (offset + gr_size < MAX_EVENT_SIZE / 2) {
				num_gr++;
				offset += gr_size;
			} else {
				// This next group record would make our event too big. So instead of adding it,
				// we return and let the caller send the current event.
				event->num_group_records = num_gr;
				event->common.size = offset & (MAX_EVENT_SIZE / 2 - 1);
				return event->common.size;
			}
		}

		probe_read_kernel(pmc_ptr, sizeof(*pmc_ptr), _(&((struct ip_mc_list *)*pmc_ptr)->next_rcu));
	}
	event->num_group_records = num_gr;
	event->common.size = offset & (MAX_EVENT_SIZE / 2 - 1);
	return event->common.size;
}

// Init a IGMPV3 event
static inline __attribute__((always_inline)) struct msg_igmp_membership_report *
igmpv3_send_report_init(struct in_device *in_dev)
{
	struct msg_igmp_membership_report *event;
	struct net_device *dev;
	struct in_ifaddr *ifa;
	int zero = 0;

	event = (struct msg_igmp_membership_report *)map_lookup_elem(&tg_h_event, &zero);
	if (!event)
		return 0;

	event->common.op = ISO_MSG_OP_IGMP_REPORT;
	event->common.ktime = tg_get_ktime();
	event->type = IGMPV3_HOST_MEMBERSHIP_REPORT;
	event->gaddr = IGMPV3_REPORT_ADDRESS;
	probe_read_kernel(&dev, sizeof(dev), _(&in_dev->dev));
	if (dev) {
		probe_read_kernel(&event->ifindex, sizeof(event->ifindex), _(&dev->ifindex));
		probe_read_kernel(&event->ifname, sizeof(event->ifname), _(&dev->name));
	} else {
		event->ifindex = 0;
		event->ifname[0] = 0;
	}
	probe_read_kernel(&ifa, sizeof(ifa), _(&in_dev->ifa_list));
	if (ifa)
		probe_read_kernel(&event->saddr, sizeof(event->saddr), _(&ifa->ifa_address));
	else
		event->saddr = 0;

	return event;
}

// In the kernel, igmpv3_send_report() operates differently depending on whether pmc is
// valid or NULL. To simplify the work for the verifer, we divide the function into two
// functions, one for each case.
static inline __attribute__((always_inline)) int
igmpv3_send_report_with_pmc(void *ctx, struct in_device *in_dev, struct ip_mc_list *pmc)
{
	struct msg_igmp_membership_report *event;
	unsigned long sfcount_mcast_exclude;
	int num_sources;
	u16 num_gr = 0;
	u16 offset = 0;
	u64 pmc_ptr;
	int type;
	u64 size;

	event = igmpv3_send_report_init(in_dev);
	if (!event)
		return 0;

	// offset points to free space after the membership report. This can be filled with
	// group records.
	offset = sizeof(struct msg_igmp_membership_report);

	// Following is modelled on igmpv3_send_report() in the kernel: /net/ipv4/igmp.c
	if (!pmc) {
		// The function demands a pmc, so nothing to do.
		return 0;
	}
	probe_read_kernel(&sfcount_mcast_exclude, sizeof(sfcount_mcast_exclude), _(&pmc->sfcount));
	if (sfcount_mcast_exclude)
		type = IGMPV3_MODE_IS_EXCLUDE;
	else
		type = IGMPV3_MODE_IS_INCLUDE;
	probe_read(&pmc_ptr, sizeof(pmc_ptr), _(&pmc));
	num_sources = add_grec(offset, pmc_ptr, type);
	if (num_sources >= 0) {
		offset += sizeof(struct msg_igmp_group_record) + (num_sources * sizeof(u32));
		num_gr++;
	}
	size = offset;
	event->num_group_records = num_gr;
	event->common.size = size;

	size &= (MAX_EVENT_SIZE / 2 - 1);
	perf_event_output_metric(ctx, ISO_MSG_OP_IGMP_REPORT, &tcpmon_map, BPF_F_CURRENT_CPU, event,
				 size);
	return 0;
}

static inline __attribute__((always_inline)) int
igmpv3_send_report_without_pmc(void *ctx, struct in_device *in_dev)
{
	struct msg_igmp_membership_report *event;
	u64 pmc_ptr;
	u64 size;

	event = igmpv3_send_report_init(in_dev);
	if (!event)
		return 0;

	// Following is modelled on igmpv3_send_report() in the kernel: /net/ipv4/igmp.c

	// Read the pmc pointer as a u64 so the verifier doesn't mind us passing it
	// around.
	probe_read_kernel(&pmc_ptr, sizeof(pmc_ptr), _(&in_dev->mc_list));
	// We need to add pmcs until the event is full, send it, and then repeat until
	// there are no more pmcs to send.
	for (u8 i = 0; i < FGS_CONFIG(TG_IGMPV3_MAX_EVENT_FRAGS); i++) {
		size = add_pmcs(&pmc_ptr);
		if (size <= 0)
			return 0;
		size &= (MAX_EVENT_SIZE / 2 - 1);
		perf_event_output_metric(ctx, ISO_MSG_OP_IGMP_REPORT, &tcpmon_map, BPF_F_CURRENT_CPU, event,
					 size);
		// Are we finished?
		if (!pmc_ptr)
			break;
	}

	return 0;
}

// checks if sysctl force_igmp_version is set on all interfaces
static inline __attribute__((always_inline)) int
all_force_igmp_version(struct in_device *in_dev)
{
	struct ipv4_devconf *devconf_all;
	struct net_device *dev;
	int force_igmp_version;
	struct net *net;

	probe_read_kernel(&dev, sizeof(dev), _(&in_dev->dev));
	if (!dev)
		return 0;
	probe_read_kernel(&net, sizeof(net), _(&dev->nd_net));
	if (!net)
		return 0;
	probe_read_kernel(&devconf_all, sizeof(devconf_all), _(&net->ipv4.devconf_all));
	if (!devconf_all)
		return 0;
	probe_read_kernel(&force_igmp_version, sizeof(force_igmp_version), _(&devconf_all->data[IPV4_DEVCONF_FORCE_IGMP_VERSION - 1]));
	return force_igmp_version;
}

// checks if sysctl force_igmp_version is set on the current interface
static inline __attribute__((always_inline)) int
dev_force_igmp_version(struct in_device *in_dev)
{
	int force_igmp_version;

	probe_read_kernel(&force_igmp_version, sizeof(force_igmp_version), _(&in_dev->cnf.data[IPV4_DEVCONF_FORCE_IGMP_VERSION]));
	return force_igmp_version;
}

// This is modelled on the IGMP_V1_SEEN macro in net/ipv4/igmp.c
__attribute__((noinline)) int
igmp_v1_seen(u64 in_dev_ptr)
{
	struct in_device *in_dev = (struct in_device *)in_dev_ptr;
	u64 jiffies = jiffies64();
	unsigned long mr_v1_seen;

	probe_read_kernel(&mr_v1_seen, sizeof(mr_v1_seen), _(&in_dev->mr_v1_seen));

	if (all_force_igmp_version(in_dev) == 1 || dev_force_igmp_version(in_dev) == 1 ||
	    (mr_v1_seen && ((long)(jiffies - mr_v1_seen) < 0)))
		return 1;
	return 0;
}

// This is modelled on the IGMP_V2_SEEN macro in net/ipv4/igmp.c
__attribute__((noinline)) int
igmp_v2_seen(u64 in_dev_ptr)
{
	struct in_device *in_dev = (struct in_device *)in_dev_ptr;
	u64 jiffies = jiffies64();
	unsigned long mr_v2_seen;

	probe_read_kernel(&mr_v2_seen, sizeof(mr_v2_seen), _(&in_dev->mr_v2_seen));

	if (all_force_igmp_version(in_dev) == 2 || dev_force_igmp_version(in_dev) == 2 ||
	    (mr_v2_seen && ((long)(jiffies - mr_v2_seen) < 0)))
		return 1;
	return 0;
}

// body of the igmp_timer_expire hooks
static inline __attribute__((always_inline)) int
igmp_timer_expire(void *ctx, struct timer_list *t)
{
	struct ip_mc_list *im = container_of_btf(t, struct ip_mc_list, timer);
	struct in_device *in_dev;

	probe_read_kernel(&in_dev, sizeof(in_dev), _(&im->interface));
	if (igmp_v1_seen((u64)in_dev))
		igmp_send_report(ctx, in_dev, im, IGMP_HOST_MEMBERSHIP_REPORT);
	else if (igmp_v2_seen((u64)in_dev))
		igmp_send_report(ctx, in_dev, im, IGMPV2_HOST_MEMBERSHIP_REPORT);
	else
#ifdef TG_IGMPV3_GROUP_RECORDS
		igmpv3_send_report_with_pmc(ctx, in_dev, im);
#else
		igmp_send_report(ctx, in_dev, im, IGMPV3_HOST_MEMBERSHIP_REPORT);
#endif
	return 0;
}

// body of the igmp_gq_timer_expire hooks
static inline __attribute__((always_inline)) int
igmp_gq_timer_expire(void *ctx, struct timer_list *t)
{
	struct in_device *in_dev = container_of_btf(t, struct in_device, mr_gq_timer);

	if (!in_dev)
		return 0;
#ifdef TG_IGMPV3_GROUP_RECORDS
	igmpv3_send_report_without_pmc(ctx, in_dev);
#else
	igmp_send_report(ctx, in_dev, 0, IGMPV3_HOST_MEMBERSHIP_REPORT);
#endif
	return 0;
}

// body of the igmp_group_dropped hooks
static inline __attribute__((always_inline)) int
igmp_group_dropped(void *ctx, struct ip_mc_list *im)
{
	struct in_device *in_dev;

	probe_read_kernel(&in_dev, sizeof(in_dev), _(&im->interface));
	igmp_send_report(ctx, in_dev, im, IGMP_HOST_LEAVE_MESSAGE);
	return 0;
}

// implemented from ip_mc_send_rejoin_groups() from the kernel
static inline __attribute__((always_inline)) int
ip_mc_send_rejoin_report(void *ctx, u64 in_dev_ptr, u64 im_ptr)
{
	struct in_device *in_dev = (struct in_device *)in_dev_ptr;
	struct ip_mc_list *im = (struct ip_mc_list *)im_ptr;
	u32 gaddr;

	probe_read_kernel(&gaddr, sizeof(gaddr), _(&im->multiaddr));
	if (gaddr == IGMP_ALL_HOSTS)
		return 0;

	if (igmp_v1_seen((u64)in_dev))
		igmp_send_report(ctx, in_dev, im, IGMP_HOST_MEMBERSHIP_REPORT);
	else if (igmp_v2_seen((u64)in_dev))
		igmp_send_report(ctx, in_dev, im, IGMPV2_HOST_MEMBERSHIP_REPORT);
	else
#ifdef TG_IGMPV3_GROUP_RECORDS
		igmpv3_send_report_with_pmc(ctx, in_dev, im);
#else
		igmp_send_report(ctx, in_dev, im, IGMPV3_HOST_MEMBERSHIP_REPORT);
#endif
	return 0;
}

// implemented ip_mc_rejoin_groups from the kernel
static inline __attribute__((always_inline)) int
ip_mc_rejoin_groups(void *ctx, struct in_device *in_dev)
{
	struct ip_mc_list *im;

	// Following is modelled on ip_mc_rejoin_groups() in the kernel: /net/ipv4/igmp.c

	// We need to replicate for_each_pmc_rtnl(in_dev, im) but the verifier will struggle
	// to accept that the loop will end. Instead, we'll do a for loop over a set range
	// and exit the loop when there are no more IP lists.
	probe_read_kernel(&im, sizeof(im), _(&in_dev->mc_list));
	for (int i = 0; i < FGS_CONFIG(TG_IGMPV3_MAX_PMCS); i++) {
		if (!im)
			break;

		ip_mc_send_rejoin_report(ctx, (u64)in_dev, (u64)im);

		probe_read_kernel(&im, sizeof(im), _(&im->next_rcu));
	}
	return 0;
}

// body of the igmp_netdev_event hooks
static inline __attribute__((always_inline)) int
igmp_netdev_event(void *ctx, void *ptr)
{
	struct netdev_notifier_info *info = (struct netdev_notifier_info *)ptr;
	struct in_device *in_dev;
	struct net_device *dev;

	probe_read_kernel(&dev, sizeof(dev), _(&info->dev));
	probe_read_kernel(&in_dev, sizeof(in_dev), _(&dev->ip_ptr));

	ip_mc_rejoin_groups(ctx, in_dev);
	return 0;
}
