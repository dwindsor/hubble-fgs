# Linux Binary tarball

For Linux Binary tarball, files should reside in /usr/local/

Tarball should be:

1. hubble-fgs.service => /usr/lib/systemd/system/

2. linux-tarball/usr => /usr/

3. empty directory /etc/hubble-fgs

4. Binaries:
   hubble-fgs		=> /usr/local/bin/
   hubble-enterprise	=> /usr/local/bin/
   hubble-enterprise	=> /usr/local/bin/hubble-fgs-printer

5. Helper Binaries:
   bpftool	=> /usr/local/lib/hubble-fgs/hubble-fgs-bpftool
   fs-scanner	=> /usr/local/lib/hubble-fgs/bpf/fs-scanner

6. BPF files
   /usr/local/lib/hubble-fgs/bpf
