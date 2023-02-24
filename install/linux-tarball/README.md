# Linux Binary tarball

For Linux Binary tarball, files should reside in /usr/local/

Tarball should be:

1. tetragon-enterprise.service:
   ```
   /usr/lib/systemd/system/tetragon-enterprise.service
   ```

2. linux-tarball/usr => /usr/

3. linux-tarball/etc => /etc/

4. Binaries:
   ```
   hubble-fgs		=> /usr/local/bin/
   hubble-enterprise	=> /usr/local/bin/
   hubble-enterprise	=> /usr/local/bin/hubble-fgs-printer
   ```

5. Helper Binaries:
   ```
   bpftool	=> /usr/local/lib/hubble-fgs/hubble-fgs-bpftool
   hubble-fgs-fs-scanner	=> /usr/local/lib/hubble-fgs/bpf/hubble-fgs-fs-scanner
   ```

6. BPF files:
   ```
   /usr/local/lib/hubble-fgs/bpf
   ```
