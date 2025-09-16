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
  vagrant destroy
  vagrant global-status --prune
  rm -rf .vagrant
  ```

### 노드 IP 수정

```bash
NODEIP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
sed -i "s/^\(KUBELET_KUBEADM_ARGS=\"\)/\1--node-ip=${NODEIP} /" /var/lib/kubelet/kubeadm-flags.env
systemctl daemon-reexec && systemctl restart kubelet

cat /var/lib/kubelet/kubeadm-flags.env
```

### KVM Module 오류 

- 에러 메세지 

```bash
There was an error while executing `VBoxManage`, a CLI used by Vagrant
for controlling VirtualBox. The command and stderr is shown below.

Command: ["startvm", "66691d5c-3f9e-40a0-a662-b67f5970d3c0", "--type", "headless"]

Stderr: VBoxManage: error: VirtualBox can't enable the AMD-V extension. Please disable the KVM kernel extension, recompile your kernel and reboot (VERR_SVM_IN_USE)
VBoxManage: error: Details: code NS_ERROR_FAILURE (0x80004005), component ConsoleWrap, interface IConsole
```

- KVM 모듈 비활성화

```bash
# 현재 실행 중인 KVM 모듈 확인
lsmod | grep kvm
# KVM 모듈 제거
sudo modprobe -r kvm_amd  # AMD CPU의 경우
sudo modprobe -r kvm_intel  # Intel CPU의 경우 (혹시 잘못 로드된 경우)
```

- 버츄얼 박스 재실행

```bash
vagrant up
```

## 네트워크 분석

- termshark 

  ```bash
  termshark -r test.pcap
  ```

- ubuntu 

  ```bash
  kubectl run ubuntu --image=ubuntu -- sleep infinity
  ```