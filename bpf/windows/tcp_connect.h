#pragma once

typedef enum _flags {
	ADDRESS_BLOCK = 0,
	ADDRESS_PERMIT = 1,
} flags;

typedef struct _address_subnet {
	union {
		uint32_t address4;
		uint8_t octet[4];
		uint32_t address16[4];
	};
	uint16_t from_port;
	uint16_t to_port;
	uint8_t subnet_mask;
	uint8_t flags;
} address_subnet;
