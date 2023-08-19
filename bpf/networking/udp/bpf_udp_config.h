#ifndef __BPF_UDP_CONFIG_H_
#define __BPF_UDP_CONFIG_H_

struct udp_sensor_config {
	u16 dnsPorts[4];
	u64 watermarks_enable;
	u64 watermarks_avg_window_size_ms;
	u64 watermarks_window_size;
	u64 watermarks_burst_trigger_percent;
	u64 watermarks_dip_trigger_percent;
	u64 seq_check_app_id;
	u16 seq_check_ports[8];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct udp_sensor_config);
	__uint(max_entries, 1);
} tg_udp_config_map SEC(".maps");

static inline __attribute__((always_inline)) struct udp_sensor_config *
get_udp_config()
{
	struct udp_sensor_config *config;
	int zero = 0;

	config = (struct udp_sensor_config *)map_lookup_elem(&tg_udp_config_map, &zero);
	return config;
}

#endif // __BPF_UDP_CONFIG_H_
