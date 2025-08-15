#!/usr/bin/env bash

echo ">>>> K8S Node config Start <<<<"

echo "[TASK 1] K8S Controlplane Join" 
NODEIP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
cat <<"EOT" > /home/vagrant/kubeadm-join-config.yaml
apiVersion: kubeadm.k8s.io/v1beta4
kind: JoinConfiguration
discovery:
  bootstrapToken:
    token: "123456.1234567890123456"
    apiServerEndpoint: "192.168.50.100:6443"
    unsafeSkipCAVerification: true 
nodeRegistration:
  criSocket: "unix:///run/containerd/containerd.sock"
  kubeletExtraArgs:
    - name: node-ip
      value: NODE_IP_PLACEHOLDER
EOT

sed -i "s/NODE_IP_PLACEHOLDER/${NODEIP}/g" /home/vagrant/kubeadm-join-config.yaml
kubeadm join --config="/home/vagrant/kubeadm-join-config.yaml" || exit 1

echo ">>>> K8S Node config End <<<<"