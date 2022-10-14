Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/impish64"
  config.vm.provision :docker
  config.vm.network "private_network", ip: "192.168.56.11"
  config.vm.synced_folder ".", "/home/vagrant/go/src/github.com/isovalent/hubble-fgs", create: true
  config.ssh.extra_args = ["-t", "cd /home/vagrant/go/src/github.com/isovalent/hubble-fgs; bash --login"]
  config.vm.provider "virtualbox" do |v|
    v.memory = 8192
    v.cpus = 2
  end

  # Mostly copied from .github/workflows/gotests.yml to install dependencies
  config.vm.provision "shell", inline: <<-SHELL
      cd /home/vagrant/go/src/github.com/isovalent/hubble-fgs
      apt-get update
      apt-get install -y build-essential clang conntrack libelf-dev net-tools
      snap install go --channel=1.16/stable --classic
      ldconfig /usr/local/

      # Install crictl
      VERSION="v1.22.0"
      wget https://github.com/kubernetes-sigs/cri-tools/releases/download/$VERSION/crictl-$VERSION-linux-amd64.tar.gz
      sudo tar zxvf crictl-$VERSION-linux-amd64.tar.gz -C /usr/local/bin
      rm -f crictl-$VERSION-linux-amd64.tar.gz
  SHELL
end
