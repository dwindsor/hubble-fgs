#!/bin/bash
# vim:noexpandtab

set -xeu -o pipefail

CONF_DIR="$(realpath $(dirname "${BASH_SOURCE[0]}")/..)"
source "$CONF_DIR/conf"

MNTDIR=/mnt
KOUT=/kout

mkimage() {
	sudo debootstrap --include=$(IFS=, ; echo "${PACKAGES[*]}") jammy $MNTDIR
	sudo cp fgs-bin/* $MNTDIR/bin
	if [ -f "$KOUT/bpftool" ]; then
		sudo cp "$KOUT/bpftool" "$MNTDIR/bin/bpftool"
	fi
	if [ -f "$KOUT/vmlinux" ]; then
		sudo cp "$KOUT/vmlinux" $MNTDIR/vmlinux
	fi
}

chrootconfig() {
	sudo chroot $MNTDIR bash <<- ENDCHROOT
		set -xeu
		# Update system packages
		apt-get -y update
		apt-get -y dist-upgrade

		# Install required base packages
		apt-get -y install openssh-server python3 curl iptables build-essential libelf-dev software-properties-common liburing-dev libcap-dev libaio-dev
		# Use iptables-legacy
		update-alternatives --set iptables /usr/sbin/iptables-legacy

 		# Add universe
		cat <<-EOF | tee /etc/apt/sources.list.d/universe.list
			deb http://archive.ubuntu.com/ubuntu jammy universe
		EOF

		# Allow passwordless root login
		passwd -d root
		systemctl enable systemd-networkd

		# Configuration for k8s
		cat <<-EOF | tee /etc/sysctl.d/k8s.conf
			net.bridge.bridge-nf-call-ip6tables = 1
			net.bridge.bridge-nf-call-iptables = 1
			net.ipv4.ip_forward = 1
		EOF
		sysctl --system

		# Add k8s to apt sources
		apt-get -y install apt-transport-https curl gnupg wget
		curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
		cat <<-EOF | tee /etc/apt/sources.list.d/kubernetes.list
			deb https://apt.kubernetes.io/ kubernetes-xenial main
		EOF

		# Add Docker to apt sources
		curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
		cat <<-EOF | tee /etc/apt/sources.list.d/docker.list
			deb https://download.docker.com/linux/ubuntu jammy stable
		EOF
		apt-get -y update

		# Install netcat-openbsd for IPv6 tests
		apt-get -y install netcat-openbsd

		# Install netcat-traditional
		apt-get -y install netcat-traditional
		update-alternatives --set nc /bin/nc.traditional

		# Install docker and k8s
		apt-mark unhold libseccomp2
		apt-get -y install -f docker-ce docker-ce-cli containerd.io kubectl
		apt-mark hold kubectl
		systemctl enable docker.service

		# Install golang
		wget https://go.dev/dl/go1.17.8.linux-amd64.tar.gz
		rm -rf /usr/local/go && tar -C /usr/local -xzf go1.17.8.linux-amd64.tar.gz
		rm -f go1.17.8.linux-amd64.tar.gz

		# Install kind
		curl -Lo ./kind "https://kind.sigs.k8s.io/dl/v0.11.1/kind-linux-amd64"
		chmod +x ./kind
		mv ./kind /bin/kind

		# Install cilium cli
		curl -sSL --remote-name-all https://github.com/cilium/cilium-cli/releases/download/v0.10.7/cilium-linux-amd64.tar.gz{,.sha256sum}
		sha256sum --check cilium-linux-amd64.tar.gz.sha256sum
		tar xzvfC cilium-linux-amd64.tar.gz /usr/bin
		rm cilium-linux-amd64.tar.gz{,.sha256sum}

		# Install helm
		curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

		# Add an fgs user
		useradd fgs -m -G docker,sudo
	ENDCHROOT
}

miscconfig() {
	cat <<- ENDSSHDCONFIG | sudo tee -a $MNTDIR/etc/ssh/sshd_config
	PermitRootLogin yes
	ENDSSHDCONFIG

	sudo mkdir $MNTDIR/root/.ssh
	cat ./id_rsa.pub | sudo tee -a $MNTDIR/root/.ssh/authorized_keys

	cat <<- ENDBASHRC | sudo tee -a  $MNTDIR/root/.bashrc
		alias k='kubectl'
		alias ks='kubectl -n kube-system'
		alias kslogs='kubectl -n kube-system logs -l k8s-app=cilium --tail=-1'
		cilium_pod() {
		    kubectl -n kube-system get pods -l k8s-app=cilium -o jsonpath="{.items[?(@.spec.nodeName == \"\$1\")].metadata.name}"
		}
		export PATH=/usr/local/go/bin:\$PATH
	ENDBASHRC

	mkdir -p $MNTDIR/lib/modules
	cat <<- ENDFSTAB | sudo tee -a  $MNTDIR/etc/fstab
		modules  /lib/modules   9p  trans=virtio,ro 0   0
		fgs  /fgs   9p  trans=virtio,rw 0   0
	ENDFSTAB

	mkdir -p $MNTDIR/etc/network
	cat <<- ENDIFACES | sudo tee -a $MNTDIR/etc/netplan/config.yaml
network:
    version: 2
    renderer: networkd
    ethernets:
        enp0s2:
            dhcp4: true
	ENDIFACES
}

mkimage
chrootconfig
miscconfig
set +x
echo "Root filesystem bootstrapped successfully!" 1>&2
