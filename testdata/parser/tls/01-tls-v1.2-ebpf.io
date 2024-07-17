INGRESSPORT 8888

EGRESS client hello
  #### TLSv1 Record Layer: Handshake Protocol: Client Hello
  $ 16    # Content Type: Handshake (22)
  $ 03 01 # Version: TLS 1.0 (0x0301)
  $ 00 d9 # Length: 217
  #### Handshake Protocol: Client Hello
  $ 01       # Handshake Type: Client Hello (1)
  $ 00 00 d5 # Length: 213
  $ 03 03    # Version: TLS 1.2 (0x0303)
  ## Random: b31deaaabeaa80823d3ded594226f57812944410c21566b33d4a7526...
  # GMT Unix Time: Mar 24, 2065 02:04:42.000000000 CET
  # Random Bytes: beaa80823d3ded594226f57812944410c21566b33d4a75261be50de9
  $ b3 1d ea aa be aa 80 82 3d 3d ed 59 42 26 f5 78 12 94 44 10 c2 15 66 b3
  $ 3d 4a 75 26 1b e5 0d e9
  $ 00    # Session ID Length: 0
  $ 00 38 # Cipher Suites Length: 56
  #### Cipher Suites (28 suites)
  $ c0 2c # Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
  $ c0 30 # Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
  $ 00 9f # Cipher Suite: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009f)
  $ cc a9 # Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xc...
  $ cc a8 # Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca...
  $ cc aa # Cipher Suite: TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xccaa)
  $ c0 2b # Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
  $ c0 2f # Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
  $ 00 9e # Cipher Suite: TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009e)
  $ c0 24 # Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xc024)
  $ c0 28 # Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)
  $ 00 6b # Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006b)
  $ c0 23 # Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xc023)
  $ c0 27 # Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027)
  $ 00 67 # Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x0067)
  $ c0 0a # Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
  $ c0 14 # Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
  $ 00 39 # Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
  $ c0 09 # Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
  $ c0 13 # Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
  $ 00 33 # Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)
  $ 00 9d # Cipher Suite: TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)
  $ 00 9c # Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
  $ 00 3d # Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)
  $ 00 3c # Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003c)
  $ 00 35 # Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
  $ 00 2f # Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
  $ 00 ff # Cipher Suite: TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)
  $ 01    # Compression Methods Length: 1
  #### Compression Methods (1 method)
  $ 00 # Compression Method: null (0)
  $ 00 74                                                 # Extensions Length: 116
  ## Extension: server_name (len=12)
  # Type: server_name (0)
  # Length: 12
  # Server Name Indication extension
  $ 00 00 00 0c 00 0a 00 00 07 65 62 70 66 2e 69 6f
  ## Extension: ec_point_formats (len=4)
  # Type: ec_point_formats (11)
  # Length: 4
  # EC point formats Length: 3
  # Elliptic curves point formats (3)
  $ 00 0b 00 04 03 00 01 02
  ## Extension: supported_groups (len=12)
  # Type: supported_groups (10)
  # Length: 12
  # Supported Groups List Length: 10
  # Supported Groups (5 groups)
  $ 00 0a 00 0c 00 0a 00 1d 00 17 00 1e 00 19 00 18
  ## Extension: next_protocol_negotiation (len=0)
  # Type: next_protocol_negotiation (13172)
  # Length: 0
  $ 33 74 00 00
  ## Extension: application_layer_protocol_negotiation (len=14)
  # Type: application_layer_protocol_negotiation (16)
  # Length: 14
  # ALPN Extension Length: 12
  # ALPN Protocol
  $ 00 10 00 0e 00 0c 02 68 32 08 68 74 74 70 2f 31 2e 31
  ## Extension: encrypt_then_mac (len=0)
  # Type: encrypt_then_mac (22)
  # Length: 0
  $ 00 16 00 00
  ## Extension: extended_master_secret (len=0)
  # Type: extended_master_secret (23)
  # Length: 0
  $ 00 17 00 00
  ## Extension: signature_algorithms (len=42)
  # Type: signature_algorithms (13)
  # Length: 42
  # Signature Hash Algorithms Length: 40
  # Signature Hash Algorithms (20 algorithms)
  $ 00 0d 00 2a 00 28 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04
  $ 08 05 08 06 04 01 05 01 06 01 03 03 03 01 03 02 04 02 05 02 06 02
END
INGRESS server hello
  #### TLSv1.2 Record Layer: Handshake Protocol: Server Hello
  $ 16    # Content Type: Handshake (22)
  $ 03 03 # Version: TLS 1.2 (0x0303)
  $ 00 62 # Length: 98
  #### Handshake Protocol: Server Hello
  $ 02       # Handshake Type: Server Hello (2)
  $ 00 00 5e # Length: 94
  $ 03 03    # Version: TLS 1.2 (0x0303)
  ## Random: 391f7c464b4df95548647db1ef6c8115ea46aa57fae27d4c444f574e...
  # GMT Unix Time: May 15, 2000 06:25:42.000000000 CEST
  # Random Bytes: 4b4df95548647db1ef6c8115ea46aa57fae27d4c444f574e47524401
  $ 39 1f 7c 46 4b 4d f9 55 48 64 7d b1 ef 6c 81 15 ea 46 aa 57 fa e2 7d 4c
  $ 44 4f 57 4e 47 52 44 01
  $ 20 # Session ID Length: 32

  ## Session ID: a267b78ddd0ee2aee05c1e9e7a02921169e76c275800b17fa954...
  $ a2 67 b7 8d dd 0e e2 ae e0 5c 1e 9e 7a 02 92 11 69 e7 6c 27 58 00 b1 7f
  $ a9 54 e0 d2 b3 5f 93 44
  $ c0 2c                      # Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
  $ 00                         # Compression Method: null (0)
  $ 00 16                      # Extensions Length: 22
  ## Extension: application_layer_protocol_negotiation (len=5)
  # Type: application_layer_protocol_negotiation (16)
  # Length: 5
  # ALPN Extension Length: 3
  # ALPN Protocol
  $ 00 10 00 05 00 03 02 68 32
  ## Extension: server_name (len=0)
  # Type: server_name (0)
  # Length: 0
  $ 00 00 00 00
  ## Extension: renegotiation_info (len=1)
  # Type: renegotiation_info (65281)
  # Length: 1
  # Renegotiation Info extension
  $ ff 01 00 01 00
  ## Extension: extended_master_secret (len=0)
  # Type: extended_master_secret (23)
  # Length: 0
  $ 00 17 00 00
END
INGRESS certs 1/4
  ## Frame: 7, payload: 0-1219 (1220 bytes)
  #### TLSv1.2 Record Layer: Handshake Protocol: Certificate (fragment)
  $ 16    # Content Type: Handshake (22)
  $ 03 03 # Version: TLS 1.2 (0x0303)
  $ 04 c4 # Length: 1220
  $ 0b 00 0e e5 00 0e e2 00 04 5b 30 82 04 57 30 82 03 3f a0 03 02 01 02 02
  $ 12 03 67 ee 29 6c 6a b4 ac 17 a2 b5 70 70 90 cb d1 f9 2c 30 0d 06 09 2a
  $ 86 48 86 f7 0d 01 01 0b 05 00 30 32 31 0b 30 09 06 03 55 04 06 13 02 55
  $ 53 31 16 30 14 06 03 55 04 0a 13 0d 4c 65 74 27 73 20 45 6e 63 72 79 70
  $ 74 31 0b 30 09 06 03 55 04 03 13 02 52 33 30 1e 17 0d 32 31 31 30 30 39
  $ 31 30 30 30 34 30 5a 17 0d 32 32 30 31 30 37 31 30 30 30 33 39 5a 30 12
  $ 31 10 30 0e 06 03 55 04 03 13 07 65 62 70 66 2e 69 6f 30 59 30 13 06 07
  $ 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07 03 42 00 04 fb 04 d7
  $ 43 d9 8f d0 2f 1b 24 8a 92 15 5f b9 24 ac a5 f5 54 e3 e0 3f f1 0c f3 5a
  $ 95 d7 ed b2 b3 80 c8 18 2d 36 85 c3 b1 b9 5b 6b c8 7c c2 22 c4 ec 19 67
  $ 49 c7 76 29 b5 ca f2 23 0f a5 fa a2 39 a3 82 02 50 30 82 02 4c 30 0e 06
  $ 03 55 1d 0f 01 01 ff 04 04 03 02 07 80 30 1d 06 03 55 1d 25 04 16 30 14
  $ 06 08 2b 06 01 05 05 07 03 01 06 08 2b 06 01 05 05 07 03 02 30 0c 06 03
  $ 55 1d 13 01 01 ff 04 02 30 00 30 1d 06 03 55 1d 0e 04 16 04 14 b7 d9 1c
  $ 82 29 85 ac 13 77 70 1f 78 85 d7 bf 3f e1 4d f0 02 30 1f 06 03 55 1d 23
  $ 04 18 30 16 80 14 14 2e b3 17 b7 58 56 cb ae 50 09 40 e6 1f af 9d 8b 14
  $ c2 c6 30 55 06 08 2b 06 01 05 05 07 01 01 04 49 30 47 30 21 06 08 2b 06
  $ 01 05 05 07 30 01 86 15 68 74 74 70 3a 2f 2f 72 33 2e 6f 2e 6c 65 6e 63
  $ 72 2e 6f 72 67 30 22 06 08 2b 06 01 05 05 07 30 02 86 16 68 74 74 70 3a
  $ 2f 2f 72 33 2e 69 2e 6c 65 6e 63 72 2e 6f 72 67 2f 30 1f 06 03 55 1d 11
  $ 04 18 30 16 82 07 65 62 70 66 2e 69 6f 82 0b 77 77 77 2e 65 62 70 66 2e
  $ 69 6f 30 4c 06 03 55 1d 20 04 45 30 43 30 08 06 06 67 81 0c 01 02 01 30
  $ 37 06 0b 2b 06 01 04 01 82 df 13 01 01 01 30 28 30 26 06 08 2b 06 01 05
  $ 05 07 02 01 16 1a 68 74 74 70 3a 2f 2f 63 70 73 2e 6c 65 74 73 65 6e 63
  $ 72 79 70 74 2e 6f 72 67 30 82 01 05 06 0a 2b 06 01 04 01 d6 79 02 04 02
  $ 04 81 f6 04 81 f3 00 f1 00 77 00 41 c8 ca b1 df 22 46 4a 10 c6 a1 3a 09
  $ 42 87 5e 4e 31 8b 1b 03 eb eb 4b c7 68 f0 90 62 96 06 f6 00 00 01 7c 64
  $ b6 49 aa 00 00 04 03 00 48 30 46 02 21 00 90 67 ed 57 6a 5e 6e d4 92 74
  $ 0f 0b 4c 47 1e 45 88 c9 5f 2a 15 40 7b 20 64 b6 1f f7 a6 b6 13 03 02 21
  $ 00 9f 96 a3 63 23 4f 4f 0a 6c d6 73 74 d5 48 e0 e9 14 3c fe 3c 93 99 1b
  $ b8 36 fb 85 8e 6f 65 19 50 00 76 00 46 a5 55 eb 75 fa 91 20 30 b5 a2 89
  $ 69 f4 f3 7d 11 2c 41 74 be fd 49 b8 85 ab f2 fc 70 fe 6d 47 00 00 01 7c
  $ 64 b6 4b d5 00 00 04 03 00 47 30 45 02 20 31 00 2a 17 08 0f b3 18 e6 27
  $ d0 07 fb 6c 0f 7d a2 50 a5 eb 36 a2 67 06 78 e2 a9 56 33 f2 73 86 02 21
  $ 00 bd 5c bd 96 4f 4b 93 91 0d fb 50 ba 14 4b bd 25 03 72 b2 7b 9d be 2d
  $ f2 33 dd da c0 e3 14 a2 74 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00
  $ 03 82 01 01 00 0c 26 ea f5 10 13 3b 6a 50 db 78 ac 13 f5 5a 8b 5a 61 ab
  $ 02 95 2c 7b 8b 66 ad e5 ff 7b c7 c8 03 19 5d 92 a0 48 55 fb 85 d5 cc 15
  $ de f7 a7 3e 56 46 44 02 db 88 60 a2 2d 4e e5 34 be 8d c0 eb 79 52 f4 7b
  $ 97 12 81 ae 35 6c 38 82 15 09 b0 30 63 49 79 41 67 b4 4c 33 42 4c 0a a7
  $ bf 3c 7e 66 4c 6b 1c 25 1f 5f 62 70 93 f6 db 42 79 01 ce ab cd d2 84 e3
  $ 60 22 e4 45 ab 4b 66 b0 72 84 3f 3c 6b 69 88 d5 2b 34 9c f2 6b 28 22 a3
  $ 92 d8 19 2a 01 1d a4 c6 2c 3b 42 16 b2 8d ce 2e 92 19 63 51 09 22 93 48
  $ 28 8a a1 88 00 a0 68 53 70 89 7a fd b2 7b 95 be ac 67 58 53 35 84 07 4f
  $ 94 c6 97 2f 79 1a 4c d9 f5 3b 77 db 09 f4 04 4d 67 fb 50 a8 6b f6 6f 9a
  $ 5b e5 b5 35 02 bd 1d 6e 32 a2 be 83 92 95 b6 80 9b 08 64 96 ad 98 d7 fc
  $ f9 74 64 e6 68 27 b8 3c 5a c9 0a d0 fc ba ad 32 e5 af 5d 90 e4 00 05 1a
  $ 30 82 05 16 30 82 02 fe a0 03 02 01 02 02 11 00 91 2b 08 4a cf 0c 18 a7
  $ 53 f6 d6 2e 25 a7 5f 5a 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30
  $ 4f 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 29 30 27 06 03 55 04 0a 13
  $ 20 49 6e 74 65 72 6e 65 74 20 53 65 63 75 72 69 74 79 20 52
END

INGRESS certs 2/4
  ## Frame: 8, payload: 1220-2439 (1220 bytes)
  #### Handshake Protocol: Certificate (fragment)
  #### TLSv1.2 Record Layer: Handshake Protocol: Multiple Handshake Mes...
  $ 16    # Content Type: Handshake (22)
  $ 03 03 # Version: TLS 1.2 (0x0303)
  $ 04 c4 # Length: 1220
  $ 65 73 65 61 72 63 68 20 47 72 6f 75 70 31 15 30 13 06 03 55 04 03 13 0c
  $ 49 53 52 47 20 52 6f 6f 74 20 58 31 30 1e 17 0d 32 30 30 39 30 34 30 30
  $ 30 30 30 30 5a 17 0d 32 35 30 39 31 35 31 36 30 30 30 30 5a 30 32 31 0b
  $ 30 09 06 03 55 04 06 13 02 55 53 31 16 30 14 06 03 55 04 0a 13 0d 4c 65
  $ 74 27 73 20 45 6e 63 72 79 70 74 31 0b 30 09 06 03 55 04 03 13 02 52 33
  $ 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00
  $ 30 82 01 0a 02 82 01 01 00 bb 02 15 28 cc f6 a0 94 d3 0f 12 ec 8d 55 92
  $ c3 f8 82 f1 99 a6 7a 42 88 a7 5d 26 aa b5 2b b9 c5 4c b1 af 8e 6b f9 75
  $ c8 a3 d7 0f 47 94 14 55 35 57 8c 9e a8 a2 39 19 f5 82 3c 42 a9 4e 6e f5
  $ 3b c3 2e db 8d c0 b0 5c f3 59 38 e7 ed cf 69 f0 5a 0b 1b be c0 94 24 25
  $ 87 fa 37 71 b3 13 e7 1c ac e1 9b ef db e4 3b 45 52 45 96 a9 c1 53 ce 34
  $ c8 52 ee b5 ae ed 8f de 60 70 e2 a5 54 ab b6 6d 0e 97 a5 40 34 6b 2b d3
  $ bc 66 eb 66 34 7c fa 6b 8b 8f 57 29 99 f8 30 17 5d ba 72 6f fb 81 c5 ad
  $ d2 86 58 3d 17 c7 e7 09 bb f1 2b f7 86 dc c1 da 71 5d d4 46 e3 cc ad 25
  $ c1 88 bc 60 67 75 66 b3 f1 18 f7 a2 5c e6 53 ff 3a 88 b6 47 a5 ff 13 18
  $ ea 98 09 77 3f 9d 53 f9 cf 01 e5 f5 a6 70 17 14 af 63 a4 ff 99 b3 93 9d
  $ dc 53 a7 06 fe 48 85 1d a1 69 ae 25 75 bb 13 cc 52 03 f5 ed 51 a1 8b db
  $ 15 02 03 01 00 01 a3 82 01 08 30 82 01 04 30 0e 06 03 55 1d 0f 01 01 ff
  $ 04 04 03 02 01 86 30 1d 06 03 55 1d 25 04 16 30 14 06 08 2b 06 01 05 05
  $ 07 03 02 06 08 2b 06 01 05 05 07 03 01 30 12 06 03 55 1d 13 01 01 ff 04
  $ 08 30 06 01 01 ff 02 01 00 30 1d 06 03 55 1d 0e 04 16 04 14 14 2e b3 17
  $ b7 58 56 cb ae 50 09 40 e6 1f af 9d 8b 14 c2 c6 30 1f 06 03 55 1d 23 04
  $ 18 30 16 80 14 79 b4 59 e6 7b b6 e5 e4 01 73 80 08 88 c8 1a 58 f6 e9 9b
  $ 6e 30 32 06 08 2b 06 01 05 05 07 01 01 04 26 30 24 30 22 06 08 2b 06 01
  $ 05 05 07 30 02 86 16 68 74 74 70 3a 2f 2f 78 31 2e 69 2e 6c 65 6e 63 72
  $ 2e 6f 72 67 2f 30 27 06 03 55 1d 1f 04 20 30 1e 30 1c a0 1a a0 18 86 16
  $ 68 74 74 70 3a 2f 2f 78 31 2e 63 2e 6c 65 6e 63 72 2e 6f 72 67 2f 30 22
  $ 06 03 55 1d 20 04 1b 30 19 30 08 06 06 67 81 0c 01 02 01 30 0d 06 0b 2b
  $ 06 01 04 01 82 df 13 01 01 01 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05
  $ 00 03 82 02 01 00 85 ca 4e 47 3e a3 f7 85 44 85 bc d5 67 78 b2 98 63 ad
  $ 75 4d 1e 96 3d 33 65 72 54 2d 81 a0 ea c3 ed f8 20 bf 5f cc b7 70 00 b7
  $ 6e 3b f6 5e 94 de e4 20 9f a6 ef 8b b2 03 e7 a2 b5 16 3c 91 ce b4 ed 39
  $ 02 e7 7c 25 8a 47 e6 65 6e 3f 46 f4 d9 f0 ce 94 2b ee 54 ce 12 bc 8c 27
  $ 4b b8 c1 98 2f a2 af cd 71 91 4a 08 b7 c8 b8 23 7b 04 2d 08 f9 08 57 3e
  $ 83 d9 04 33 0a 47 21 78 09 82 27 c3 2a c8 9b b9 ce 5c f2 64 c8 c0 be 79
  $ c0 4f 8e 6d 44 0c 5e 92 bb 2e f7 8b 10 e1 e8 1d 44 29 db 59 20 ed 63 b9
  $ 21 f8 12 26 94 93 57 a0 1d 65 04 c1 0a 22 ae 10 0d 43 97 a1 18 1f 7e e0
  $ e0 86 37 b5 5a b1 bd 30 bf 87 6e 2b 2a ff 21 4e 1b 05 c3 f5 18 97 f0 5e
  $ ac c3 a5 b8 6a f0 2e bc 3b 33 b9 ee 4b de cc fc e4 af 84 0b 86 3f c0 55
  $ 43 36 f6 68 e1 36 17 6a 8e 99 d1 ff a5 40 a7 34 b7 c0 d0 63 39 35 39 75
  $ 6e f2 ba 76 c8 93 02 e9 a9 4b 6c 17 ce 0c 02 d9 bd 81 fb 9f b7 68 d4 06
  $ 65 b3 82 3d 77 53 f8 8e 79 03 ad 0a 31 07 75 2a 43 d8 55 97 72 c4 29 0e
  $ f7 c4 5d 4e c8 ae 46 84 30 d7 f2 85 5f 18 a1 79 bb e7 5e 70 8b 07 e1 86
  $ 93 c3 b9 8f dc 61 71 25 2a af df ed 25 50 52 68 8b 92 dc e5 d6 b5 e3 da
  $ 7d d0 87 6c 84 21 31 ae 82 f5 fb b9 ab c8 89 17 3d e1 4c e5 38 0e f6 bd
  $ 2b bd 96 81 14 eb d5 db 3d 20 a7 7e 59 d3 e2 f8 58 f9 5b b8 48 cd fe 5c
  $ 4f 16 29 fe 1e 55 23 af c8 11 b0 8d ea 7c 93 90 17 2f fd ac a2 09 47 46
  $ 3f f0 e9 b0 b7 ff 28 4d 68 32 d6 67 5e 1e 69 a3 93 b8 f5 9d 8b 2f 0b d2
  $ 52 43 a6 6f 32 57 65 4d 32 81 df 38 53 85 5d 7e 5d 66 29 ea b8 dd e4 95
  $ b5 cd b5 56 12 42 cd c4 4e c6 25 38 44 50 6d ec ce 00 55 18 fe e9 49 64
  $ d4 4e ca 97 9c b4 5b c0 73 a8 ab b8 47 c2 00 05 64 30 82 05
END

INGRESS certs 3/4
  ## Frame: 9, payload: 2440-3659 (1220 bytes)
  #### Handshake Protocol: Certificate (fragment)
  #### TLSv1.2 Record Layer: Handshake Protocol: Multiple Handshake Mes...
  $ 16    # Content Type: Handshake (22)
  $ 03 03 # Version: TLS 1.2 (0x0303)
  $ 04 c4 # Length: 1220
  #### Handshake Protocol: Certificate (fragment)
  $ 60 30 82 04 48 a0 03 02 01 02 02 10 40 01 77 21 37 d4 e9 42 b8 ee 76 aa
  $ 3c 64 0a b7 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 3f 31 24 30
  $ 22 06 03 55 04 0a 13 1b 44 69 67 69 74 61 6c 20 53 69 67 6e 61 74 75 72
  $ 65 20 54 72 75 73 74 20 43 6f 2e 31 17 30 15 06 03 55 04 03 13 0e 44 53
  $ 54 20 52 6f 6f 74 20 43 41 20 58 33 30 1e 17 0d 32 31 30 31 32 30 31 39
  $ 31 34 30 33 5a 17 0d 32 34 30 39 33 30 31 38 31 34 30 33 5a 30 4f 31 0b
  $ 30 09 06 03 55 04 06 13 02 55 53 31 29 30 27 06 03 55 04 0a 13 20 49 6e
  $ 74 65 72 6e 65 74 20 53 65 63 75 72 69 74 79 20 52 65 73 65 61 72 63 68
  $ 20 47 72 6f 75 70 31 15 30 13 06 03 55 04 03 13 0c 49 53 52 47 20 52 6f
  $ 6f 74 20 58 31 30 82 02 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00
  $ 03 82 02 0f 00 30 82 02 0a 02 82 02 01 00 ad e8 24 73 f4 14 37 f3 9b 9e
  $ 2b 57 28 1c 87 be dc b7 df 38 90 8c 6e 3c e6 57 a0 78 f7 75 c2 a2 fe f5
  $ 6a 6e f6 00 4f 28 db de 68 86 6c 44 93 b6 b1 63 fd 14 12 6b bf 1f d2 ea
  $ 31 9b 21 7e d1 33 3c ba 48 f5 dd 79 df b3 b8 ff 12 f1 21 9a 4b c1 8a 86
  $ 71 69 4a 66 66 6c 8f 7e 3c 70 bf ad 29 22 06 f3 e4 c0 e6 80 ae e2 4b 8f
  $ b7 99 7e 94 03 9f d3 47 97 7c 99 48 23 53 e8 38 ae 4f 0a 6f 83 2e d1 49
  $ 57 8c 80 74 b6 da 2f d0 38 8d 7b 03 70 21 1b 75 f2 30 3c fa 8f ae dd da
  $ 63 ab eb 16 4f c2 8e 11 4b 7e cf 0b e8 ff b5 77 2e f4 b2 7b 4a e0 4c 12
  $ 25 0c 70 8d 03 29 a0 e1 53 24 ec 13 d9 ee 19 bf 10 b3 4a 8c 3f 89 a3 61
  $ 51 de ac 87 07 94 f4 63 71 ec 2e e2 6f 5b 98 81 e1 89 5c 34 79 6c 76 ef
  $ 3b 90 62 79 e6 db a4 9a 2f 26 c5 d0 10 e1 0e de d9 10 8e 16 fb b7 f7 a8
  $ f7 c7 e5 02 07 98 8f 36 08 95 e7 e2 37 96 0d 36 75 9e fb 0e 72 b1 1d 9b
  $ bc 03 f9 49 05 d8 81 dd 05 b4 2a d6 41 e9 ac 01 76 95 0a 0f d8 df d5 bd
  $ 12 1f 35 2f 28 17 6c d2 98 c1 a8 09 64 77 6e 47 37 ba ce ac 59 5e 68 9d
  $ 7f 72 d6 89 c5 06 41 29 3e 59 3e dd 26 f5 24 c9 11 a7 5a a3 4c 40 1f 46
  $ a1 99 b5 a7 3a 51 6e 86 3b 9e 7d 72 a7 12 05 78 59 ed 3e 51 78 15 0b 03
  $ 8f 8d d0 2f 05 b2 3e 7b 4a 1c 4b 73 05 12 fc c6 ea e0 50 13 7c 43 93 74
  $ b3 ca 74 e7 8e 1f 01 08 d0 30 d4 5b 71 36 b4 07 ba c1 30 30 5c 48 b7 82
  $ 3b 98 a6 7d 60 8a a2 a3 29 82 cc ba bd 83 04 1b a2 83 03 41 a1 d6 05 f1
  $ 1b c2 b6 f0 a8 7c 86 3b 46 a8 48 2a 88 dc 76 9a 76 bf 1f 6a a5 3d 19 8f
  $ eb 38 f3 64 de c8 2b 0d 0a 28 ff f7 db e2 15 42 d4 22 d0 27 5d e1 79 fe
  $ 18 e7 70 88 ad 4e e6 d9 8b 3a c6 dd 27 51 6e ff bc 64 f5 33 43 4f 02 03
  $ 01 00 01 a3 82 01 46 30 82 01 42 30 0f 06 03 55 1d 13 01 01 ff 04 05 30
  $ 03 01 01 ff 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 01 06 30 4b 06 08
  $ 2b 06 01 05 05 07 01 01 04 3f 30 3d 30 3b 06 08 2b 06 01 05 05 07 30 02
  $ 86 2f 68 74 74 70 3a 2f 2f 61 70 70 73 2e 69 64 65 6e 74 72 75 73 74 2e
  $ 63 6f 6d 2f 72 6f 6f 74 73 2f 64 73 74 72 6f 6f 74 63 61 78 33 2e 70 37
  $ 63 30 1f 06 03 55 1d 23 04 18 30 16 80 14 c4 a7 b1 a4 7b 2c 71 fa db e1
  $ 4b 90 75 ff c4 15 60 85 89 10 30 54 06 03 55 1d 20 04 4d 30 4b 30 08 06
  $ 06 67 81 0c 01 02 01 30 3f 06 0b 2b 06 01 04 01 82 df 13 01 01 01 30 30
  $ 30 2e 06 08 2b 06 01 05 05 07 02 01 16 22 68 74 74 70 3a 2f 2f 63 70 73
  $ 2e 72 6f 6f 74 2d 78 31 2e 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67
  $ 30 3c 06 03 55 1d 1f 04 35 30 33 30 31 a0 2f a0 2d 86 2b 68 74 74 70 3a
  $ 2f 2f 63 72 6c 2e 69 64 65 6e 74 72 75 73 74 2e 63 6f 6d 2f 44 53 54 52
  $ 4f 4f 54 43 41 58 33 43 52 4c 2e 63 72 6c 30 1d 06 03 55 1d 0e 04 16 04
  $ 14 79 b4 59 e6 7b b6 e5 e4 01 73 80 08 88 c8 1a 58 f6 e9 9b 6e 30 0d 06
  $ 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 0a 73 00 6c 96 6e ff
  $ 0e 52 d0 ae dd 8c e7 5a 06 ad 2f a8 e3 8f bf c9 0a 03 15 50 c2 e5 6c 42
  $ bb 6f 9b f4 b4 4f c2 44 88 08 75 cc eb 07 9b 14 62 6e 78 de ec 27 ba 39
  $ 5c f5 a2 a1 6e 56 94 70 10 53 b1 bb e4 af d0 a2 c3 2b 01 d4 96 f4 c5 20
  $ 35 33 f9 d8 61 36 e0 71 8d b4 b8 b5 aa 82 45 95 c0 f2 a9 23
END

INGRESS certs 4/4
  ## Frame: 10, payload: 3660-3816 (157 bytes)
  #### TLSv1.2 Record Layer: Handshake Protocol: Certificate
  $ 16    # Content Type: Handshake (22)
  $ 03 03 # Version: TLS 1.2 (0x0303)
  $ 00 9d # Length: 157
  #### Handshake Protocol: Certificate (last fragment)
  $ 28 e7 d6 a1 cb 67 08 da a0 43 2c aa 1b 93 1f c9 de f5 ab 69 5d 13 f5 5b
  $ 86 58 22 ca 4d 55 e4 70 67 6d c2 57 c5 46 39 41 cf 8a 58 83 58 6d 99 fe
  $ 57 e8 36 0e f0 0e 23 aa fd 88 97 d0 e3 5c 0e 94 49 b5 b5 17 35 d2 2e bf
  $ 4e 85 ef 18 e0 85 92 eb 06 3b 6c 29 23 09 60 dc 45 02 4c 12 18 3b e9 fb
  $ 0e de dc 44 f8 58 98 ae ea bd 45 45 a1 88 5d 66 ca fe 10 e9 6f 82 c8 11
  $ 42 0d fb e9 ec e3 86 00 de 9d 10 e3 38 fa a4 7d b1 d8 e8 49 82 84 06 9b
  $ 2b e8 6b 4f 01 0c 38 77 2e f9 dd e7 39

  #### TLSv1.2 Record Layer: Handshake Protocol: Server Key Exchange
  $ 16    # Content Type: Handshake (22)
  $ 03 03 # Version: TLS 1.2 (0x0303)
  $ 00 74 # Length: 116
  #### Handshake Protocol: Server Key Exchange
  $ 0c       # Handshake Type: Server Key Exchange (12)
  $ 00 00 70 # Length: 112
  ## EC Diffie-Hellman Server Params
  # Curve Type: named_curve (0x03)
  # Named Curve: x25519 (0x001d)
  # Pubkey Length: 32
  # Pubkey: 7612868eaea5dd8dfb9bd426ae368a8df7261b57946d7bb31c5b29369aa73d12
  # Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
  # Signature Length: 72
  # Signature: 3046022100edf6b00077438a093710f43dd1b955c67684039a1f239110a1c9c25c330f8c…
  $ 03 00 1d 20 76 12 86 8e ae a5 dd 8d fb 9b d4 26 ae 36 8a 8d f7 26 1b 57
  $ 94 6d 7b b3 1c 5b 29 36 9a a7 3d 12 04 03 00 48 30 46 02 21 00 ed f6 b0
  $ 00 77 43 8a 09 37 10 f4 3d d1 b9 55 c6 76 84 03 9a 1f 23 91 10 a1 c9 c2
  $ 5c 33 0f 8c be 02 21 00 bb c4 23 c5 4a 9e 80 7d 3b 00 89 26 ae d9 54 4f
  $ 94 ab 97 9d ac 50 75 8b 46 7d 67 22 5f ac 1e 4f
  #### TLSv1.2 Record Layer: Handshake Protocol: Server Hello Done
  $ 16    # Content Type: Handshake (22)
  $ 03 03 # Version: TLS 1.2 (0x0303)
  $ 00 04 # Length: 4
  #### Handshake Protocol: Server Hello Done
  $ 0e       # Handshake Type: Server Hello Done (14)
  $ 00 00 00 # Length: 0
END

EGRESS key exchange
  #### TLSv1.2 Record Layer: Handshake Protocol: Client Key Exchange
  $ 16    # Content Type: Handshake (22)
  $ 03 03 # Version: TLS 1.2 (0x0303)
  $ 00 25 # Length: 37
  #### Handshake Protocol: Client Key Exchange
  $ 10       # Handshake Type: Client Key Exchange (16)
  $ 00 00 21 # Length: 33
  ## EC Diffie-Hellman Client Params
  # Pubkey Length: 32
  # Pubkey: ab4cf569f4907390bd01a1d8d20ddc8e52af4201ea67462ffafe1fd4e95a0c30
  $ 20 ab 4c f5 69 f4 90 73 90 bd 01 a1 d8 d2 0d dc 8e 52 af 42 01 ea 67 46
  $ 2f fa fe 1f d4 e9 5a 0c 30
  #### TLSv1.2 Record Layer: Change Cipher Spec Protocol: Change Cipher...
  $ 14    # Content Type: Change Cipher Spec (20)
  $ 03 03 # Version: TLS 1.2 (0x0303)
  $ 00 01 # Length: 1
  #### Change Cipher Spec Message
  #### TLSv1.2 Record Layer: Handshake Protocol: Encrypted Handshake Me...
  $ 16    # Content Type: Handshake (22)
  $ 03 03 # Version: TLS 1.2 (0x0303)
  $ 00 28 # Length: 40
  #### Handshake Protocol: Encrypted Handshake Message
END

INGRESS change cipher spec
  #### TLSv1.2 Record Layer: Change Cipher Spec Protocol: Change Cipher...
  $ 14    # Content Type: Change Cipher Spec (20)
  $ 03 03 # Version: TLS 1.2 (0x0303)
  $ 00 01 # Length: 1
  #### Change Cipher Spec Message
END

INGRESS encrypted handshake
  #### TLSv1.2 Record Layer: Handshake Protocol: Encrypted Handshake Me...
  $ 16    # Content Type: Handshake (22)
  $ 03 03 # Version: TLS 1.2 (0x0303)
  $ 00 28 # Length: 40
  #### Handshake Protocol: Encrypted Handshake Message
END
EGRESS encrypted data
  #### TLSv1.2 Record Layer: Application Data Protocol: http2
  $ 17    # Content Type: Application Data (23)
  $ 03 03 # Version: TLS 1.2 (0x0303)
  $ 00 30 # Length: 48

  ## Encrypted Application Data: 6e2f980f32538ee01924c0d9ad995db849ad...
  $ 6e 2f 98 0f 32 53 8e e0 19 24 c0 d9 ad 99 5d b8 49 ad cb 65 99 08 a5 72
  $ d4 fd 35 7c d7 35 c8 bf fa c4 54 78 3b a4 4b 1e 3e a1 65 05 64 dd 9d 48
END
INGRESS encrypted data
  #### TLSv1.2 Record Layer: Application Data Protocol: http2
  $ 17    # Content Type: Application Data (23)
  $ 03 03 # Version: TLS 1.2 (0x0303)
  $ 00 2d # Length: 45

  ## Encrypted Application Data: af35380a8c931bbd954b811d424b360eb83f...
  $ af 35 38 0a 8c 93 1b bd 95 4b 81 1d 42 4b 36 0e b8 3f a6 ac 24 dd b1 2e
  $ 52 d0 15 15 5a 71 bc ce 61 89 83 28 6c 11 d2 eb 0c 63 b0 04 4e
END

EVENT tls
  $ 06 00 00 00             # op + pad
  h4 512                    # size
  $ ?? ?? ?? ?? ?? ?? ?? ?? # ktime

  ## socket cookie
  ? 8                       # socket cookie
  ? 8                       # version and pad

  ## Client hello
  $ 03 03       # version v1.2
  2 217         # length
  $ 16 01 00 00 # handshake, client_hello, negotiated version

  # flags
  h4 0x000

  # bytes
  $ 00 00 00 00

  # alert level & description
  $ 00 00

  # session id
  $ 00
  ? 64

  # cipher
  $ 38
  $ c0 2c c0 30 00 9f cc a9 cc a8 cc aa c0 2b c0 2f
  $ 00 9e c0 24 c0 28 00 6b c0 23 c0 27 00 67 c0 0a
  $ c0 14 00 39 c0 09 c0 13 00 33 00 9d 00 9c 00 3d
  $ 00 3c 00 35 00 2f 00 ff ?? ?? ?? ?? ?? ?? ?? ??

  # sni: ebpf.io
  $ 0c
  2 10          # list len
  $ 00          # type host_name
  2 7           # name len
  "ebpf.io"
  ? 52          # SNI padding

  # supported versions
  $ 00
  ? 16
  $ 00 00 # pad

  ## Server hello
  $ 03 03 # version
  $ 00 62 # length
  $ 16 02 00 00 # handshake, server_hello, version

  # flags (TLS_CERT)
  h4 0x800

  # bytes
  $ 00 00 00 00

  # alert level & description
  $ 00 00

  # Session ID
  $ 20
  $ a2 67 b7 8d dd 0e e2 ae e0 5c 1e 9e 7a 02 92 11
  $ 69 e7 6c 27 58 00 b1 7f a9 54 e0 d2 b3 5f 93 44
  ? 32

  # cipher
  $ 02
  $ c0 2c
  ? 62

  # sni (not set)
  $ 00
  ? 64

  # supported versions
  $ 00
  ? 16
  $ 00 00 # pad

  # process key
  NZ 4          # pid
  $ 00 00 00 00 # pad
  NZ 8          # ktime

  $ 00 00 00 00 # padding inserted by the perf ring
END

EVENT tlscont
  ## op (TLSCONT)
  $ 0c

  ## socket cookie
  ? 8                       # socket cookie
  ? 8                       # version and pad

  ## length
  h4 3837

  ## certificates
  $ 16 03 03
  $ 04 c4 0b 00 0e e5 00 0e e2 00 04 5b 30 82 04 57
  $ 30 82 03 3f a0 03 02 01 02 02 12 03 67 ee 29 6c
  $ 6a b4 ac 17 a2 b5 70 70 90 cb d1 f9 2c 30 0d 06
  $ 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 32 31 0b
  $ 30 09 06 03 55 04 06 13 02 55 53 31 16 30 14 06
  $ 03 55 04 0a 13 0d 4c 65 74 27 73 20 45 6e 63 72
  $ 79 70 74 31 0b 30 09 06 03 55 04 03 13 02 52 33
  $ 30 1e 17 0d 32 31 31 30 30 39 31 30 30 30 34 30
  $ 5a 17 0d 32 32 30 31 30 37 31 30 30 30 33 39 5a
  $ 30 12 31 10 30 0e 06 03 55 04 03 13 07 65 62 70
  $ 66 2e 69 6f 30 59 30 13 06 07 2a 86 48 ce 3d 02
  $ 01 06 08 2a 86 48 ce 3d 03 01 07 03 42 00 04 fb
  $ 04 d7 43 d9 8f d0 2f 1b 24 8a 92 15 5f b9 24 ac
  $ a5 f5 54 e3 e0 3f f1 0c f3 5a 95 d7 ed b2 b3 80
  $ c8 18 2d 36 85 c3 b1 b9 5b 6b c8 7c c2 22 c4 ec
  $ 19 67 49 c7 76 29 b5 ca f2 23 0f a5 fa a2 39 a3
  $ 82 02 50 30 82 02 4c 30 0e 06 03 55 1d 0f 01 01
  $ ff 04 04 03 02 07 80 30 1d 06 03 55 1d 25 04 16
  $ 30 14 06 08 2b 06 01 05 05 07 03 01 06 08 2b 06
  $ 01 05 05 07 03 02 30 0c 06 03 55 1d 13 01 01 ff
  $ 04 02 30 00 30 1d 06 03 55 1d 0e 04 16 04 14 b7
  $ d9 1c 82 29 85 ac 13 77 70 1f 78 85 d7 bf 3f e1
  $ 4d f0 02 30 1f 06 03 55 1d 23 04 18 30 16 80 14
  $ 14 2e b3 17 b7 58 56 cb ae 50 09 40 e6 1f af 9d
  $ 8b 14 c2 c6 30 55 06 08 2b 06 01 05 05 07 01 01
  $ 04 49 30 47 30 21 06 08 2b 06 01 05 05 07 30 01
  $ 86 15 68 74 74 70 3a 2f 2f 72 33 2e 6f 2e 6c 65
  $ 6e 63 72 2e 6f 72 67 30 22 06 08 2b 06 01 05 05
  $ 07 30 02 86 16 68 74 74 70 3a 2f 2f 72 33 2e 69
  $ 2e 6c 65 6e 63 72 2e 6f 72 67 2f 30 1f 06 03 55
  $ 1d 11 04 18 30 16 82 07 65 62 70 66 2e 69 6f 82
  $ 0b 77 77 77 2e 65 62 70 66 2e 69 6f 30 4c 06 03
  $ 55 1d 20 04 45 30 43 30 08 06 06 67 81 0c 01 02
  $ 01 30 37 06 0b 2b 06 01 04 01 82 df 13 01 01 01
  $ 30 28 30 26 06 08 2b 06 01 05 05 07 02 01 16 1a
  $ 68 74 74 70 3a 2f 2f 63 70 73 2e 6c 65 74 73 65
  $ 6e 63 72 79 70 74 2e 6f 72 67 30 82 01 05 06 0a
  $ 2b 06 01 04 01 d6 79 02 04 02 04 81 f6 04 81 f3
  $ 00 f1 00 77 00 41 c8 ca b1 df 22 46 4a 10 c6 a1
  $ 3a 09 42 87 5e 4e 31 8b 1b 03 eb eb 4b c7 68 f0
  $ 90 62 96 06 f6 00 00 01 7c 64 b6 49 aa 00 00 04
  $ 03 00 48 30 46 02 21 00 90 67 ed 57 6a 5e 6e d4
  $ 92 74 0f 0b 4c 47 1e 45 88 c9 5f 2a 15 40 7b 20
  $ 64 b6 1f f7 a6 b6 13 03 02 21 00 9f 96 a3 63 23
  $ 4f 4f 0a 6c d6 73 74 d5 48 e0 e9 14 3c fe 3c 93
  $ 99 1b b8 36 fb 85 8e 6f 65 19 50 00 76 00 46 a5
  $ 55 eb 75 fa 91 20 30 b5 a2 89 69 f4 f3 7d 11 2c
  $ 41 74 be fd 49 b8 85 ab f2 fc 70 fe 6d 47 00 00
  $ 01 7c 64 b6 4b d5 00 00 04 03 00 47 30 45 02 20
  $ 31 00 2a 17 08 0f b3 18 e6 27 d0 07 fb 6c 0f 7d
  $ a2 50 a5 eb 36 a2 67 06 78 e2 a9 56 33 f2 73 86
  $ 02 21 00 bd 5c bd 96 4f 4b 93 91 0d fb 50 ba 14
  $ 4b bd 25 03 72 b2 7b 9d be 2d f2 33 dd da c0 e3
  $ 14 a2 74 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b
  $ 05 00 03 82 01 01 00 0c 26 ea f5 10 13 3b 6a 50
  $ db 78 ac 13 f5 5a 8b 5a 61 ab 02 95 2c 7b 8b 66
  $ ad e5 ff 7b c7 c8 03 19 5d 92 a0 48 55 fb 85 d5
  $ cc 15 de f7 a7 3e 56 46 44 02 db 88 60 a2 2d 4e
  $ e5 34 be 8d c0 eb 79 52 f4 7b 97 12 81 ae 35 6c
  $ 38 82 15 09 b0 30 63 49 79 41 67 b4 4c 33 42 4c
  $ 0a a7 bf 3c 7e 66 4c 6b 1c 25 1f 5f 62 70 93 f6
  $ db 42 79 01 ce ab cd d2 84 e3 60 22 e4 45 ab 4b
  $ 66 b0 72 84 3f 3c 6b 69 88 d5 2b 34 9c f2 6b 28
  $ 22 a3 92 d8 19 2a 01 1d a4 c6 2c 3b 42 16 b2 8d
  $ ce 2e 92 19 63 51 09 22 93 48 28 8a a1 88 00 a0
  $ 68 53 70 89 7a fd b2 7b 95 be ac 67 58 53 35 84
  $ 07 4f 94 c6 97 2f 79 1a 4c d9 f5 3b 77 db 09 f4
  $ 04 4d 67 fb 50 a8 6b f6 6f 9a 5b e5 b5 35 02 bd
  $ 1d 6e 32 a2 be 83 92 95 b6 80 9b 08 64 96 ad 98
  $ d7 fc f9 74 64 e6 68 27 b8 3c 5a c9 0a d0 fc ba
  $ ad 32 e5 af 5d 90 e4 00 05 1a 30 82 05 16 30 82
  $ 02 fe a0 03 02 01 02 02 11 00 91 2b 08 4a cf 0c
  $ 18 a7 53 f6 d6 2e 25 a7 5f 5a 30 0d 06 09 2a 86
  $ 48 86 f7 0d 01 01 0b 05 00 30 4f 31 0b 30 09 06
  $ 03 55 04 06 13 02 55 53 31 29 30 27 06 03 55 04
  $ 0a 13 20 49 6e 74 65 72 6e 65 74 20 53 65 63 75
  $ 72 69 74 79 20 52 16 03 03 04 c4 65 73 65 61 72
  $ 63 68 20 47 72 6f 75 70 31 15 30 13 06 03 55 04
  $ 03 13 0c 49 53 52 47 20 52 6f 6f 74 20 58 31 30
  $ 1e 17 0d 32 30 30 39 30 34 30 30 30 30 30 30 5a
  $ 17 0d 32 35 30 39 31 35 31 36 30 30 30 30 5a 30
  $ 32 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 16
  $ 30 14 06 03 55 04 0a 13 0d 4c 65 74 27 73 20 45
  $ 6e 63 72 79 70 74 31 0b 30 09 06 03 55 04 03 13
  $ 02 52 33 30 82 01 22 30 0d 06 09 2a 86 48 86 f7
  $ 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02
  $ 82 01 01 00 bb 02 15 28 cc f6 a0 94 d3 0f 12 ec
  $ 8d 55 92 c3 f8 82 f1 99 a6 7a 42 88 a7 5d 26 aa
  $ b5 2b b9 c5 4c b1 af 8e 6b f9 75 c8 a3 d7 0f 47
  $ 94 14 55 35 57 8c 9e a8 a2 39 19 f5 82 3c 42 a9
  $ 4e 6e f5 3b c3 2e db 8d c0 b0 5c f3 59 38 e7 ed
  $ cf 69 f0 5a 0b 1b be c0 94 24 25 87 fa 37 71 b3
  $ 13 e7 1c ac e1 9b ef db e4 3b 45 52 45 96 a9 c1
  $ 53 ce 34 c8 52 ee b5 ae ed 8f de 60 70 e2 a5 54
  $ ab b6 6d 0e 97 a5 40 34 6b 2b d3 bc 66 eb 66 34
  $ 7c fa 6b 8b 8f 57 29 99 f8 30 17 5d ba 72 6f fb
  $ 81 c5 ad d2 86 58 3d 17 c7 e7 09 bb f1 2b f7 86
  $ dc c1 da 71 5d d4 46 e3 cc ad 25 c1 88 bc 60 67
  $ 75 66 b3 f1 18 f7 a2 5c e6 53 ff 3a 88 b6 47 a5
  $ ff 13 18 ea 98 09 77 3f 9d 53 f9 cf 01 e5 f5 a6
  $ 70 17 14 af 63 a4 ff 99 b3 93 9d dc 53 a7 06 fe
  $ 48 85 1d a1 69 ae 25 75 bb 13 cc 52 03 f5 ed 51
  $ a1 8b db 15 02 03 01 00 01 a3 82 01 08 30 82 01
  $ 04 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 01
  $ 86 30 1d 06 03 55 1d 25 04 16 30 14 06 08 2b 06
  $ 01 05 05 07 03 02 06 08 2b 06 01 05 05 07 03 01
  $ 30 12 06 03 55 1d 13 01 01 ff 04 08 30 06 01 01
  $ ff 02 01 00 30 1d 06 03 55 1d 0e 04 16 04 14 14
  $ 2e b3 17 b7 58 56 cb ae 50 09 40 e6 1f af 9d 8b
  $ 14 c2 c6 30 1f 06 03 55 1d 23 04 18 30 16 80 14
  $ 79 b4 59 e6 7b b6 e5 e4 01 73 80 08 88 c8 1a 58
  $ f6 e9 9b 6e 30 32 06 08 2b 06 01 05 05 07 01 01
  $ 04 26 30 24 30 22 06 08 2b 06 01 05 05 07 30 02
  $ 86 16 68 74 74 70 3a 2f 2f 78 31 2e 69 2e 6c 65
  $ 6e 63 72 2e 6f 72 67 2f 30 27 06 03 55 1d 1f 04
  $ 20 30 1e 30 1c a0 1a a0 18 86 16 68 74 74 70 3a
  $ 2f 2f 78 31 2e 63 2e 6c 65 6e 63 72 2e 6f 72 67
  $ 2f 30 22 06 03 55 1d 20 04 1b 30 19 30 08 06 06
  $ 67 81 0c 01 02 01 30 0d 06 0b 2b 06 01 04 01 82
  $ df 13 01 01 01 30 0d 06 09 2a 86 48 86 f7 0d 01
  $ 01 0b 05 00 03 82 02 01 00 85 ca 4e 47 3e a3 f7
  $ 85 44 85 bc d5 67 78 b2 98 63 ad 75 4d 1e 96 3d
  $ 33 65 72 54 2d 81 a0 ea c3 ed f8 20 bf 5f cc b7
  $ 70 00 b7 6e 3b f6 5e 94 de e4 20 9f a6 ef 8b b2
  $ 03 e7 a2 b5 16 3c 91 ce b4 ed 39 02 e7 7c 25 8a
  $ 47 e6 65 6e 3f 46 f4 d9 f0 ce 94 2b ee 54 ce 12
  $ bc 8c 27 4b b8 c1 98 2f a2 af cd 71 91 4a 08 b7
  $ c8 b8 23 7b 04 2d 08 f9 08 57 3e 83 d9 04 33 0a
  $ 47 21 78 09 82 27 c3 2a c8 9b b9 ce 5c f2 64 c8
  $ c0 be 79 c0 4f 8e 6d 44 0c 5e 92 bb 2e f7 8b 10
  $ e1 e8 1d 44 29 db 59 20 ed 63 b9 21 f8 12 26 94
  $ 93 57 a0 1d 65 04 c1 0a 22 ae 10 0d 43 97 a1 18
  $ 1f 7e e0 e0 86 37 b5 5a b1 bd 30 bf 87 6e 2b 2a
  $ ff 21 4e 1b 05 c3 f5 18 97 f0 5e ac c3 a5 b8 6a
  $ f0 2e bc 3b 33 b9 ee 4b de cc fc e4 af 84 0b 86
  $ 3f c0 55 43 36 f6 68 e1 36 17 6a 8e 99 d1 ff a5
  $ 40 a7 34 b7 c0 d0 63 39 35 39 75 6e f2 ba 76 c8
  $ 93 02 e9 a9 4b 6c 17 ce 0c 02 d9 bd 81 fb 9f b7
  $ 68 d4 06 65 b3 82 3d 77 53 f8 8e 79 03 ad 0a 31
  $ 07 75 2a 43 d8 55 97 72 c4 29 0e f7 c4 5d 4e c8
  $ ae 46 84 30 d7 f2 85 5f 18 a1 79 bb e7 5e 70 8b
  $ 07 e1 86 93 c3 b9 8f dc 61 71 25 2a af df ed 25
  $ 50 52 68 8b 92 dc e5 d6 b5 e3 da 7d d0 87 6c 84
  $ 21 31 ae 82 f5 fb b9 ab c8 89 17 3d e1 4c e5 38
  $ 0e f6 bd 2b bd 96 81 14 eb d5 db 3d 20 a7 7e 59
  $ d3 e2 f8 58 f9 5b b8 48 cd fe 5c 4f 16 29 fe 1e
  $ 55 23 af c8 11 b0 8d ea 7c 93 90 17 2f fd ac a2
  $ 09 47 46 3f f0 e9 b0 b7 ff 28 4d 68 32 d6 67 5e
  $ 1e 69 a3 93 b8 f5 9d 8b 2f 0b d2 52 43 a6 6f 32
  $ 57 65 4d 32 81 df 38 53 85 5d 7e 5d 66 29 ea b8
  $ dd e4 95 b5 cd b5 56 12 42 cd c4 4e c6 25 38 44
  $ 50 6d ec ce 00 55 18 fe e9 49 64 d4 4e ca 97 9c
  $ b4 5b c0 73 a8 ab b8 47 c2 00 05 64 30 82 05 16
  $ 03 03 04 c4 60 30 82 04 48 a0 03 02 01 02 02 10
  $ 40 01 77 21 37 d4 e9 42 b8 ee 76 aa 3c 64 0a b7
  $ 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30
  $ 3f 31 24 30 22 06 03 55 04 0a 13 1b 44 69 67 69
  $ 74 61 6c 20 53 69 67 6e 61 74 75 72 65 20 54 72
  $ 75 73 74 20 43 6f 2e 31 17 30 15 06 03 55 04 03
  $ 13 0e 44 53 54 20 52 6f 6f 74 20 43 41 20 58 33
  $ 30 1e 17 0d 32 31 30 31 32 30 31 39 31 34 30 33
  $ 5a 17 0d 32 34 30 39 33 30 31 38 31 34 30 33 5a
  $ 30 4f 31 0b 30 09 06 03 55 04 06 13 02 55 53 31
  $ 29 30 27 06 03 55 04 0a 13 20 49 6e 74 65 72 6e
  $ 65 74 20 53 65 63 75 72 69 74 79 20 52 65 73 65
  $ 61 72 63 68 20 47 72 6f 75 70 31 15 30 13 06 03
  $ 55 04 03 13 0c 49 53 52 47 20 52 6f 6f 74 20 58
  $ 31 30 82 02 22 30 0d 06 09 2a 86 48 86 f7 0d 01
  $ 01 01 05 00 03 82 02 0f 00 30 82 02 0a 02 82 02
  $ 01 00 ad e8 24 73 f4 14 37 f3 9b 9e 2b 57 28 1c
  $ 87 be dc b7 df 38 90 8c 6e 3c e6 57 a0 78 f7 75
  $ c2 a2 fe f5 6a 6e f6 00 4f 28 db de 68 86 6c 44
  $ 93 b6 b1 63 fd 14 12 6b bf 1f d2 ea 31 9b 21 7e
  $ d1 33 3c ba 48 f5 dd 79 df b3 b8 ff 12 f1 21 9a
  $ 4b c1 8a 86 71 69 4a 66 66 6c 8f 7e 3c 70 bf ad
  $ 29 22 06 f3 e4 c0 e6 80 ae e2 4b 8f b7 99 7e 94
  $ 03 9f d3 47 97 7c 99 48 23 53 e8 38 ae 4f 0a 6f
  $ 83 2e d1 49 57 8c 80 74 b6 da 2f d0 38 8d 7b 03
  $ 70 21 1b 75 f2 30 3c fa 8f ae dd da 63 ab eb 16
  $ 4f c2 8e 11 4b 7e cf 0b e8 ff b5 77 2e f4 b2 7b
  $ 4a e0 4c 12 25 0c 70 8d 03 29 a0 e1 53 24 ec 13
  $ d9 ee 19 bf 10 b3 4a 8c 3f 89 a3 61 51 de ac 87
  $ 07 94 f4 63 71 ec 2e e2 6f 5b 98 81 e1 89 5c 34
  $ 79 6c 76 ef 3b 90 62 79 e6 db a4 9a 2f 26 c5 d0
  $ 10 e1 0e de d9 10 8e 16 fb b7 f7 a8 f7 c7 e5 02
  $ 07 98 8f 36 08 95 e7 e2 37 96 0d 36 75 9e fb 0e
  $ 72 b1 1d 9b bc 03 f9 49 05 d8 81 dd 05 b4 2a d6
  $ 41 e9 ac 01 76 95 0a 0f d8 df d5 bd 12 1f 35 2f
  $ 28 17 6c d2 98 c1 a8 09 64 77 6e 47 37 ba ce ac
  $ 59 5e 68 9d 7f 72 d6 89 c5 06 41 29 3e 59 3e dd
  $ 26 f5 24 c9 11 a7 5a a3 4c 40 1f 46 a1 99 b5 a7
  $ 3a 51 6e 86 3b 9e 7d 72 a7 12 05 78 59 ed 3e 51
  $ 78 15 0b 03 8f 8d d0 2f 05 b2 3e 7b 4a 1c 4b 73
  $ 05 12 fc c6 ea e0 50 13 7c 43 93 74 b3 ca 74 e7
  $ 8e 1f 01 08 d0 30 d4 5b 71 36 b4 07 ba c1 30 30
  $ 5c 48 b7 82 3b 98 a6 7d 60 8a a2 a3 29 82 cc ba
  $ bd 83 04 1b a2 83 03 41 a1 d6 05 f1 1b c2 b6 f0
  $ a8 7c 86 3b 46 a8 48 2a 88 dc 76 9a 76 bf 1f 6a
  $ a5 3d 19 8f eb 38 f3 64 de c8 2b 0d 0a 28 ff f7
  $ db e2 15 42 d4 22 d0 27 5d e1 79 fe 18 e7 70 88
  $ ad 4e e6 d9 8b 3a c6 dd 27 51 6e ff bc 64 f5 33
  $ 43 4f 02 03 01 00 01 a3 82 01 46 30 82 01 42 30
  $ 0f 06 03 55 1d 13 01 01 ff 04 05 30 03 01 01 ff
  $ 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 01 06
  $ 30 4b 06 08 2b 06 01 05 05 07 01 01 04 3f 30 3d
  $ 30 3b 06 08 2b 06 01 05 05 07 30 02 86 2f 68 74
  $ 74 70 3a 2f 2f 61 70 70 73 2e 69 64 65 6e 74 72
  $ 75 73 74 2e 63 6f 6d 2f 72 6f 6f 74 73 2f 64 73
  $ 74 72 6f 6f 74 63 61 78 33 2e 70 37 63 30 1f 06
  $ 03 55 1d 23 04 18 30 16 80 14 c4 a7 b1 a4 7b 2c
  $ 71 fa db e1 4b 90 75 ff c4 15 60 85 89 10 30 54
  $ 06 03 55 1d 20 04 4d 30 4b 30 08 06 06 67 81 0c
  $ 01 02 01 30 3f 06 0b 2b 06 01 04 01 82 df 13 01
  $ 01 01 30 30 30 2e 06 08 2b 06 01 05 05 07 02 01
  $ 16 22 68 74 74 70 3a 2f 2f 63 70 73 2e 72 6f 6f
  $ 74 2d 78 31 2e 6c 65 74 73 65 6e 63 72 79 70 74
  $ 2e 6f 72 67 30 3c 06 03 55 1d 1f 04 35 30 33 30
  $ 31 a0 2f a0 2d 86 2b 68 74 74 70 3a 2f 2f 63 72
  $ 6c 2e 69 64 65 6e 74 72 75 73 74 2e 63 6f 6d 2f
  $ 44 53 54 52 4f 4f 54 43 41 58 33 43 52 4c 2e 63
  $ 72 6c 30 1d 06 03 55 1d 0e 04 16 04 14 79 b4 59
  $ e6 7b b6 e5 e4 01 73 80 08 88 c8 1a 58 f6 e9 9b
  $ 6e 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00
  $ 03 82 01 01 00 0a 73 00 6c 96 6e ff 0e 52 d0 ae
  $ dd 8c e7 5a 06 ad 2f a8 e3 8f bf c9 0a 03 15 50
  $ c2 e5 6c 42 bb 6f 9b f4 b4 4f c2 44 88 08 75 cc
  $ eb 07 9b 14 62 6e 78 de ec 27 ba 39 5c f5 a2 a1
  $ 6e 56 94 70 10 53 b1 bb e4 af d0 a2 c3 2b 01 d4
  $ 96 f4 c5 20 35 33 f9 d8 61 36 e0 71 8d b4 b8 b5
  $ aa 82 45 95 c0 f2 a9 23 16 03 03 00 9d 28 e7 d6
  $ a1 cb 67 08 da a0 43 2c aa 1b 93 1f c9 de f5 ab
  $ 69 5d 13 f5 5b 86 58 22 ca 4d 55 e4 70 67 6d c2
  $ 57 c5 46 39 41 cf 8a 58 83 58 6d 99 fe 57 e8 36
  $ 0e f0 0e 23 aa fd 88 97 d0 e3 5c 0e 94 49 b5 b5
  $ 17 35 d2 2e bf 4e 85 ef 18 e0 85 92 eb 06 3b 6c
  $ 29 23 09 60 dc 45 02 4c 12 18 3b e9 fb 0e de dc
  $ 44 f8 58 98 ae ea bd 45 45 a1 88 5d 66 ca fe 10
  $ e9 6f 82 c8 11 42 0d fb e9 ec e3 86 00 de 9d 10
  $ e3 38 fa a4 7d b1 d8 e8 49 82 84 06 9b 2b e8 6b
  $ 4f 01 0c 38 77 2e f9 dd e7 39 00 00
END

