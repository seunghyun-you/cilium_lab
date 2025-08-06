#!/usr/bin/env bash

echo ">>>> K8S Node config Start <<<<"


echo "[TASK 1] K8S Controlplane Join"
NODEIP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
sed -i "s/NODE_IP_PLACEHOLDER/${NODEIP}/g" /home/vagrant/kubeadm-join-config.yaml
kubeadm join --config="/home/vagrant/kubeadm-join-config.yaml" > /dev/null 2>&1


echo ">>>> K8S Node config End <<<<"