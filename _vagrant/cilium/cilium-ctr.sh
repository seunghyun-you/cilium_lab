#!/usr/bin/env bash

# ENV SETTING
K8S_VERSION=$1 # Vagrantfile에서 전달된 K8SV 값
CILIUMV=$2 # Vagrantfile에서 전달된 CONTAINERDV 값
NODES=$3

echo ">>>> K8S Controlplane config Start <<<<"

echo "[TASK 1] Initial Kubernetes"
# kubeadm init --token 123456.1234567890123456 --token-ttl 0 --pod-network-cidr=10.244.0.0/16 --service-cidr=10.96.0.0/16 --apiserver-advertise-address=192.168.10.100 --cri-socket=unix:///run/containerd/containerd.sock >/dev/null 2>&1
sed -i "s|PLACEHOLDER_K8S_VERSION|${K8S_VERSION}|g" /home/vagrant/kubeadm-config.yaml
kubeadm init --config="/home/vagrant/kubeadm-config.yaml" --skip-phases=addon/kube-proxy  >/dev/null 2>&1


echo "[TASK 2] Setting kube config file"
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown $(id -u):$(id -g) /root/.kube/config


echo "[TASK 3] Source the completion"
echo 'source <(kubectl completion bash)' >> /etc/profile
echo 'source <(kubeadm completion bash)' >> /etc/profile


echo "[TASK 4] Alias kubectl to k"
echo 'alias k=kubectl' >> /etc/profile
echo 'alias kc=kubecolor' >> /etc/profile
echo 'complete -F __start_kubectl k' >> /etc/profile


echo "[TASK 5] Install Kubectx & Kubens"
git clone https://github.com/ahmetb/kubectx /opt/kubectx >/dev/null 2>&1
ln -s /opt/kubectx/kubens /usr/local/bin/kubens
ln -s /opt/kubectx/kubectx /usr/local/bin/kubectx


echo "[TASK 6] Install Kubeps & Setting PS1"
git clone https://github.com/jonmosco/kube-ps1.git /root/kube-ps1 >/dev/null 2>&1
cat <<"EOT" >> /root/.bash_profile
source /root/kube-ps1/kube-ps1.sh
KUBE_PS1_SYMBOL_ENABLE=true
function get_cluster_short() {
  echo "${NODES}" | cut -d . -f1
}
KUBE_PS1_CLUSTER_FUNCTION=get_cluster_short
KUBE_PS1_SUFFIX=') '
PS1='$(kube_ps1)'$PS1
EOT
kubectl config rename-context "kubernetes-admin@kubernetes" "HomeLab" >/dev/null 2>&1


# Cilium Install
# --set endpointHealthChecking.enabled=false --set healthChecking=false 옵션은 노드 20대 이상일 경우 꺼두는 것이 성능에 좋다. 
echo "[TASK 7] Install Cilium CNI"
NODEIP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1
helm repo update >/dev/null 2>&1
helm install cilium cilium/cilium --version ${CILIUMV} --namespace kube-system \
--set k8sServiceHost=192.168.10.100 \
--set k8sServicePort=6443 \
--set ipam.mode="cluster-pool" \
--set ipam.operator.clusterPoolIPv4PodCIDRList={"172.20.0.0/16"} \
--set ipv4NativeRoutingCIDR=172.20.0.0/16 \
--set routingMode=native \
--set autoDirectNodeRoutes=true \
--set endpointRoutes.enabled=true \
--set kubeProxyReplacement=true \
--set bpf.masquerade=true \
--set installNoConntrackIptablesRules=true \
--set endpointHealthChecking.enabled=false \
--set healthChecking=false \
--set hubble.enabled=false \
--set operator.replicas=1 \
--set debug.enabled=true >/dev/null 2>&1


echo "[TASK 8] Install Cilium CLI"
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
CLI_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz >/dev/null 2>&1
tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
rm cilium-linux-${CLI_ARCH}.tar.gz


echo "[TASK 9] local DNS with hosts file"
echo "192.168.10.100 cilium-ctr" >> /etc/hosts
for (( i=1; i<=${NODES}; i++  )); do echo "192.168.10.10$i cilium-w$i" >> /etc/hosts; done


echo ">>>> K8S Controlplane Config End <<<<"