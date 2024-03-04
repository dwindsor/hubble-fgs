# Linux Binary tarball

For Linux Binary tarball, files should reside in /usr/local/

Tarball should be:

1. tetragon-enterprise.service:
   ```
   /usr/lib/systemd/system/tetragon-enterprise.service
   ```

1. linux-tarball/usr => /usr/

1. linux-tarball/etc => /etc/

1. Binaries:
   ```
   tetragon	=> /usr/local/bin/
   tetra	=> /usr/local/bin/
   ```

1. Symbolic links:
   ```
   hubble-fgs		=> /usr/local/bin/tetragon
   hubble-enterprise	=> /usr/local/bin/tetra
   hubble-fgs-printer	=> /usr/local/bin/tetra
   ```

1. Helper Binaries:
   ```
   bpftool	=> /usr/local/lib/hubble-fgs/hubble-fgs-bpftool
   tetragon-fs-scanner	=> /usr/local/lib/hubble-fgs/bpf/tetragon-fs-scanner
   ```

1. BPF files:
   ```
   /usr/local/lib/hubble-fgs/bpf
   ```
