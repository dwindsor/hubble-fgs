Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"
  config.vm.provision :docker
  config.vm.synced_folder ".", "/home/vagrant/go/src/github.com/isovalent/hubble-fgs", create: true
  config.ssh.extra_args = ["-t", "cd /home/vagrant/go/src/github.com/isovalent/hubble-fgs; bash --login"]

  # Mostly copied from .github/workflows/gotests.yml to install dependencies
  config.vm.provision "shell", inline: <<-SHELL
      cd /home/vagrant/go/src/github.com/isovalent/hubble-fgs
      apt-get update
      apt-get install -y build-essential clang libelf-dev
      snap install go --channel=1.16/stable --classic
      make tools-install LIBBPF_INSTALL_DIR=/usr/local/lib CLANG_INSTALL_DIR=/usr/bin
      ldconfig /usr/local/
  SHELL
end
