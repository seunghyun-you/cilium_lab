## 실습 환경 구성

1. Virtual Box 설치 - https://www.virtualbox.org/wiki/Downloads

2. Vagrant 설치 - https://developer.hashicorp.com/vagrant/downloads#windows

### vagrant 명령

- 설치 명령

  ```bash
  vagrant up
  ```

- 삭제 명령

  ```bash
  vagrant destroy -f && rm -rf .vagrant
  vagrant global-status --prune
  ```

### 노드 IP 수정

```bash
NODEIP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
sed -i "s/^\(KUBELET_KUBEADM_ARGS=\"\)/\1--node-ip=${NODEIP} /" /var/lib/kubelet/kubeadm-flags.env
systemctl daemon-reexec && systemctl restart kubelet

cat /var/lib/kubelet/kubeadm-flags.env
```

## 네트워크 분석

- termshark 

  ```bash
  termshark -r test.pcap
  ```