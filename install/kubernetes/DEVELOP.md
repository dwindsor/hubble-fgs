# Using the Latest Unreleased Chart

The latest `hubble-enterprise` Helm chart from master branch is published as version `9999.9999.9999-dev`.
You can use the latest chart as a "standalone" chart for testing. For example, to install the latest FGS
with the latest `hubble-enterprise` Helm chart on minikube:

0. Start minikube. Something like this:

       minikube start --network-plugin=cni --memory=4096 --driver=virtualbox \
         --iso-url=https://github.com/kubernetes/minikube/releases/download/v1.15.0/minikube-v1.15.0.iso
       minikube ssh -- sudo mount bpffs -t bpf /sys/fs/bpf

   Check https://docs.isovalent.com/quick-start/connectivity_visibility.html#start-minikube for the up-to-date
   instructions on how to start minikube.

1. Install `cilium-enterprise`, but with `hubble-enterprise.enabled=false`:

       helm repo add isovalent https://helm.isovalent.com
       helm repo update
       helm install -n kube-system cilium-enterprise isovalent/cilium-enterprise --version 1.9.7+4 \
         --set hubble-enterprise.enabled=false

2. Install `hubble-enterprise`, specifying the image tag you are using:

       helm install -n kube-system hubble-enterprise isovalent/hubble-enterprise --version 9999.9999.9999-dev \
         --set enterprise.image.tag=latest --set imagePullPolicy=Always

   Alternatively, if you want to use the local chart to test your change, run:

       helm install -n kube-system hubble-enterprise . \
         --set enterprise.image.tag=latest --set imagePullPolicy=Always
