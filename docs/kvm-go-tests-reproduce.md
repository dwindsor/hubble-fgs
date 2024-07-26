# Running KVM go tests locally

For OSS, see: https://github.com/cilium/tetragon/tree/main/tests/vmtests

Figure out what lvh image version you are using.

```
yq '.jobs.run-tests.strategy.matrix.kernel' .github/workflows/kvm-gotests.yaml
```
```
# renovate: datasource=docker depName=quay.io/lvh-images/kind
- 'rhel8-20240404.144247'
# renovate: datasource=docker depName=quay.io/lvh-images/kind
- 'bpf-next-20240618.013132'
# renovate: datasource=docker depName=quay.io/lvh-images/kind
- "6.6-20240612.090637"
# renovate: datasource=docker depName=quay.io/lvh-images/kind
- "6.1-20240612.090637"
# renovate: datasource=docker depName=quay.io/lvh-images/kind
- "5.15-20240612.090637"
# renovate: datasource=docker depName=quay.io/lvh-images/kind
- "5.10-20240612.090637"
# renovate: datasource=docker depName=quay.io/lvh-images/kind
- "5.4-20240612.090637"
# renovate: datasource=docker depName=quay.io/lvh-images/kind
- "4.19-20240612.090637"
```

Depending on what kernel you want to debug, pull it in.
```
lvh images pull quay.io/lvh-images/kind:6.1-20240612.090637
```

Boot a VM:
```
lvh run --image _data/images/kind_6.1.qcow2 --host-mount ~/ -p 2222:22 # this will mount your ~/ under host, port-forward ssh
```

Compile the test on your repo:
```
make test-compile TEST_COMPILE=./pkg/sensors/file
```

SSH into the VM:
```
ssh root@localhost -p 2222
```

From inside the VM, run the test.
```
cd /host/<src_dir_on_host>
./go-tests/pkg.sensors.file  -bpf-lib ./bpf/objs/ -test.run TestFileEnforceCreate
```

Some times the tests might make assumptions that break running them as above:

```
time="2024-07-26T14:08:08Z" level=info msg="BTF discovery: default kernel btf file found" btf-file=/sys/kernel/btf/vmlinux                                                                                                                                                                                                     
--- FAIL: TestFileEnforceCreate (0.19s)                                                                                                                                                                                                                                                                                        
    file_test.go:1027: open /home/kkourt/<src-dir>/testdata/specs/file_monitoring_enforce.yaml.tmpl: no such file or directory                                                                                                                                                                    
FAIL                                                                                                                                                                  
```

Ideally, we can fix the tests to execute properly, but in the meantime it's typically easy to circumvent these limitations:
```
mount --bind /host/ /home/kkourt
```

And now, we can reproduce:
```
./go-tests/pkg.sensors.file  -bpf-lib ./bpf/objs/ -test.run TestFileEnforceCreate
```

```
observer_test_helper.go:429: SensorManager.AddTracingPolicy error: sensor fim_sensor_1 from collection file-monitoring-enforce failed to load: failed prog bpf/objs/bpf_security_mmap_file_lsm.o kern_version 393565 loadInstance: opening collection 'bpf/objs/bpf_security_mmap_file_lsm.o' failed: program security_mmap_file_lsm: attach LSM/LSMMac: security_mmap_file LSM hook not supported
```
