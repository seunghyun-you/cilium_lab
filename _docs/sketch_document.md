## Cilium Lab

### 1. [Getting Started with Cilium](https://isovalent.com/labs/cilium-getting-started/)

#### 교육 목차

- Install Cilium

- Deploy a demo app

- Deploy L3/L4 Network Policy

- Apply and Test HTTP-aware L7 Policy

#### Install Cilium

```bash
cilium install
cilium status --wait
```

#### Deploy a demo app

① Sample Application 배포 (스타워즈 앱)

```bash
kubectl apply -f https://raw.githubusercontent.com/cilium/cilium/HEAD/examples/minikube/http-sw-app.yaml
```

② 배포된 Application 조회

Cilium을 사용하면 POD들이 Cilium Enpoint로 표현된다. Cilium Endpoint를 조회할 때는 `cep` 를 사용한다.

```bash
$ kubectl api-resources | grep cep
ciliumendpoints                     cep,ciliumep                        cilium.io/v2                      true         CiliumEndpoint
```

```bash
$ kubectl get cep -A
NAMESPACE            NAME                                      SECURITY IDENTITY   ENDPOINT STATE   IPV4           IPV6
default              deathstar-67c5c5c88-6dgct                 15889               ready            10.244.1.145
default              deathstar-67c5c5c88-qwgnq                 15889               ready            10.244.2.5
default              tiefighter                                6845                ready            10.244.1.147
default              xwing                                     35328               ready            10.244.1.192
kube-system          coredns-6f6b679f8f-l5gbh                  24629               ready            10.244.2.101
kube-system          coredns-6f6b679f8f-rd7v9                  24629               ready            10.244.2.137
local-path-storage   local-path-provisioner-57c5987fd4-wd6fl   44814               ready            10.244.2.84
```

#### Deploy L3/L4 Network Policy

Cilium에서는 Cilium Network Policy를 이용해서 L3, L4 계층(IP/Port) 기반 접근 통제뿐만 아니라 파드에 할당된 Lable을 기반으로 통신하거나 접근 통제가 가능하다. 이 기능은 클라우트 네이티브 환경에 조금 더 적합한 방식이다. 더불어 HTTP 요청을 제어하는 L7 계층 제어도 가능하다.

① Cilium Network Policy Sample (Label & Port 기반 접근 통제)

```yaml
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: "rule1"
spec:
  description: "L3-L4 policy to restrict deathstar access to empire ships only"
  endpointSelector:
    matchLabels:
      org: empire
      class: deathstar
  ingress:
    - fromEndpoints:
        - matchLabels:
            org: empire
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
```

② Cilium Network Policy Sample (L7 계층 접근 통제)

```yaml
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: "rule1"
spec:
  description: "L3-L4 policy to restrict deathstar access to empire ships only"
  endpointSelector:
    matchLabels:
      org: empire
      class: deathstar
  ingress:
    - fromEndpoints:
        - matchLabels:
            org: empire
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
          rules:
            http:
              - method: POST
                path: /v1/request-landing
```

③ 배포 후 조회

```bash
kubectl api-resources | grep cnp
ciliumclusterwidenetworkpolicies    ccnp                                cilium.io/v2                      false        CiliumClusterwideNetworkPolicy
ciliumnetworkpolicies               cnp,ciliumnp                        cilium.io/v2                      true         CiliumNetworkPolicy
```

```bash
kubectl get cnp -A
NAMESPACE   NAME    AGE   VALID
```

## eBPF

### 개요

- eBPF는 BPF의 기능이 개선된 확장 버전이다.

- BPF는 커널안에서 실행되는 VM이라고 생각하면 된다.

- 커널을 재 컴파일하지 않아도 커널 수준의 코드를 실행할 수 있게 해준다.

- 특정한 이벤트가 발생 했을 때 내가 만든 프로그램이 커널에서 실행될 수 있도록 지원해주는 기술이다.

- 프로세스가 eBPF Hook Point를 지나갈 때 사용자가 만든 eBPF 프로그램이 실행된다.

- eBPF Map에 실행 상태, 결과를 기록하고 그 값을 User Space에서 공유받을 수 있다.

### eBPF 샘플 코드

```python
#!/usr/bin/python3
from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

b.trace_print()
```

- program 변수에 C언어로 작성된 코드를 넣는다.

- BPF 클래스를 임포트 후 BPF 객체에 C언어 코드를 문자열로 컴파일하여 담는다.

- get_syscall_fnname 함수는 파라미터로 전달된 시스템 콜이 커널 내부의 특정 함수에서 실행될 때 그 함수의 이름을 가져오는 함수다.

- attach_kprobe는 특정 커널 함수의 호출과 BPF 객체에 담긴 코드를 연동해 커널 함수의 호출이 실행될 때마다 객체의 코드를 실행시킨다.

- get_syscall_fnname, attach_kprobe는은 BCC(BPF Compiler Collection) 라이브러리에서 제공하는 Python 함수

- bpf_trace_printk는 BPF의 helper 함수 (커널 공간에서 디버그 정보를 출력하는 데 사용)

- trace_print(): eBPF 프로그램에서 생성된 출력을 화면에 표시한다.

### eBPF Map

- eBPF 프로그램과 사용자 공간 간에 데이터를 전달하는 데 사용할 수 있는 기능이다.

- 커널의 eBPF 프로그램 내부와 사용자 공간 애플리케이션에서 액세스할 수 있는 데이터 구조를 가지고 있다.

- eBPF 프로그램과 사용자 공간 코드 간에 정보를 공유한다.

- 구성을 eBPF 프로그램으로 전달하거나 커널에서 수집된 관찰 데이터를 사용자 공간으로 보낼 수 있다.

### BPF Maps

eBPF(Extended Berkeley Packet Filter)에서 데이터를 저장하고 관리하기 위해 사용되는 자료 구조다. 저장할 수 있는 데이터의 양에 제한이 있다.

#### 1. BPF Maps 저장소 구조

- key : value 구조로 데이터 저장

- Hash Map, Array Map, Per-CPU Map, LRU Map 4가지 유형의 Map 지원

  - Hash Map : 키를 해시하여 저장하는 방식

  - Array Map : 정수 인덱스를 사용하여 값을 저장하는 배열 형태

  - Per-CPU Map : 각 CPU 마다 별도의 데이터를 저장하는 방식

  - LRU(Least Recently Used) Map : 메모리가 부족할 때 가장 오랫동안 사용되지 않은 데이터를 삭제하는 방식

```python
#!/usr/bin/python3
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table);

int hello(void *ctx) {
   u64 uid;
   u64 counter = 0;
   u64 *p;

   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   p = counter_table.lookup(&uid);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&uid, &counter);
   return 0;
}
"""

b = BPF(text=program)
# syscall = b.get_syscall_fnname("execve")
# b.attach_kprobe(event=syscall, fn_name="hello")

# Attach to a tracepoint that gets hit for all syscalls
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
```

- BPF_HASH는 eBPF에서 제공하는 매크로 → 키-값 쌍을 저장할 수 있는 해시 테이블을 생성

  - 이 이름을 통해 eBPF 프로그램 내에서 이 테이블에 접근

  - u64 타입의 키와 값을 사용

### 참고 자료

- https://tech.ktcloud.com/250

## Hubble

- Hubble은 클라우드 네이티브 워크로드를 위한 완전 분산형 네트워킹 및 보안 관찰 플랫폼

- Kubernetes 클러스터의 네트워크 및 보안 계층에 대한 클러스터 전체 가시성을 확보하는 데 사용

- Hubble은 오픈 소스 소프트웨어이며 Cilium과 eBPF를 기반으로 구축

- Hubble을 활성화하려면 Cilium을 실행하는 모든 노드에서 TCP 포트 4244가 열려 있어야 합니다.

## Cilium 실 사용자 후기

### [reddit : Cilium vs Calico K3S](https://www.reddit.com/r/kubernetes/comments/11pgmsa/cilium_vs_calico_k3s_what_do_you_use_and_why/?tl=ko)

- 온프레미스 / AWS에서 Cilium 사용 중

  - 클러스터 규모가 커서 kube-proxy가 iptables 규칙 따라가는데 걸리는 시간이 많이(70초 수준) 소요된다.

    - AWS : m6i.24xlarge(96v CPU, 384 Memory) ᳵ 350 ea / Pod ᳵ 15,000 ea

    - 온프레미스 : Node ᳵ 400 ea / Pod ᳵ 36,000 ea / Service ᳵ 27,000 ea

  - L7 네트워크 정책을 유용하게 쓰고 있다.

- 설정이 쉽지 않아서 각 기능들을 올바르게 이해하고 사용해야 한다. 러닝 커브를 극복하고 나면 사용하기 좋다.

## LAB URL

- https://isovalent.com/resource-library/labs/

### 주요 도구

#### yq

- YAML, JSON, XML 등의 구조화된 데이터를 처리하고 조작하기 위한 커맨드라인 도구
- jq 영감을 받아서 만들어진 도구

```bash
yq /etc/kind/${KIND_CONFIG}.yaml
yq '.key.subkey' file.yaml
```

## Cilium basic

- 클러스터에 Cilium을 설치

```bash
cilium install
```

- 상태를 확인

```bash
cilium status --wait
```

- 각 포드는 Cilium에서 Endpoint로 표현
- 엔드포인트 목록을 검색

```bash
kubectl get cep --all-namespaces
```

- Network Policy 만들기
- Label 정보를 기반으로 통제

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: rule1
spec:
  endpointSelector:
    matchLabels:
      org: empire
      class: deathstar
  ingress:
    - fromEndpoints:
        - matchLabels:
            org: empire
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
          rules:
            http:
              - method: POST
                path: /v1/request-landing
```

## Cilium BGP

### 상태 확인

```
cilium status --wait
```

### 오버레이 / 다이렉트 라우팅

- Cilium을 사용하면 오버레이 네트워크(Geneve의 VXLAN) 또는 직접 라우팅을 사용하여 Kubernetes 클러스터를 구성할 수 있습니다.
- Cilium을 사용하면 오버레이 네트워크(Geneve의 VXLAN) 또는 직접 라우팅을 사용하여 Kubernetes 클러스터를 구성할 수 있습니다.

### BGP 피어링 상태

```bash
$ kubectl get ciliumbgpclusterconfig
NAME            AGE
control-plane   70m
worker          70m
worker2         70m
$ kubectl get ciliumbgpclusterconfig control-plane -o yaml | yq '.spec'
bgpInstances:
  - localASN: 65001       # control plane의 ASN
    name: instance-65001
    peers:
      - name: peer-65000
        peerASN: 65000    # Top of Rack ROUTER의 ASN
        peerAddress: fd00:10:0:1::1 # Top of Rack ROUTER의 IPv6 (cilium은 ipv6도 지원)
        peerConfigRef:
          group: cilium.io
          kind: CiliumBGPPeerConfig
          name: generic
nodeSelector:
  matchLabels:
    kubernetes.io/hostname: kind-control-plane
$ cilium bgp peers
Node                 Local AS   Peer AS   Peer Address     Session State   Uptime     Family         Received   Advertised
kind-control-plane   65001      65000     fd00:10:0:1::1   established     1h13m41s   ipv4/unicast   3          1
                                                                                      ipv6/unicast   3          1
kind-worker          65002      65000     fd00:10:0:2::1   established     1h13m41s   ipv4/unicast   3          1
                                                                                      ipv6/unicast   3          1
kind-worker2         65003      65000     fd00:10:0:3::1   established     1h13m41s   ipv4/unicast   3          1
                                                                                      ipv6/unicast   3          1
```

### 로드밸런서 IP 주소 관리(LB-IPAM)

- LoadBalancer IP 주소 관리(LB-IPAM)는 Cilium이 Kubernetes LoadBalancer 서비스에 대한 IP 주소를 프로비저닝할 수 있게 해주는 새로운 고급 기능입니다.
- 클러스터 외부에 노출된 Kubernetes 서비스에 IP 주소를 할당하려면 유형의 리소스가 필요합니다 LoadBalancer. 클라우드 공급자에서 Kubernetes를 사용하면 이러한 리소스가 자동으로 관리되고 해당 IP 및/또는 DNS가 자동으로 할당됩니다. 그러나 베어 메탈 클러스터에서 실행하는 경우 과거에는 해당 주소를 할당하기 위해 MetalLB와 같은 다른 도구가 필요했습니다.
- 하지만 또 다른 네트워킹 도구를 유지 관리하는 것은 번거로울 수 있으며 Cilium 1.13에서는 더 이상 필요하지 않습니다. Cilium은 Kubernetes LoadBalancer 서비스에 IP 주소를 할당할 수 있습니다.
- IP 주소를 할당하려면 CRD를 사용하여 Cilium LB IP 풀을 구성해야 합니다.

```bash
---
apiVersion: "cilium.io/v2alpha1"
kind: CiliumLoadBalancerIPPool
metadata:
  name: "empire-ip-pool"
spec:
  blocks:
    - cidr: "172.18.255.200/29"
    - cidr: "2001:db8:dead:beef::0/64"
  serviceSelector:
    matchLabels:
      org: empire
```

- 배포 후 결과 확인

```bash
$ kubectl apply -f lb-pool.yaml
$ kubectl get ciliumloadbalancerippools.cilium.io empire-ip-pool
NAME             DISABLED   CONFLICTING   IPS AVAILABLE          AGE
empire-ip-pool   false      False         18446744073709551622   6s
$ kubectl -n batuu get svc deathstar
NAME        TYPE           CLUSTER-IP     EXTERNAL-IP                           PORT(S)        AGE
deathstar   LoadBalancer   10.2.206.153   172.18.255.200,2001:db8:dead:beef::   80:32141/TCP   11m
```

### L2 IP 발표

- Cilium 1.13 버전부터 클러스터 내에서 North-South 로드 밸런서 서비스를 생성하고 BGP를 사용하여 기본 네트워크에 이를 알리는 방법을 제공했습니다 .
- 하지만 온프레미스 Kubernetes 클러스터를 보유한 모든 사람이 BGP 호환 인프라를 갖고 있는 것은 아닙니다.
- 이러한 이유로 Cilium은 이제 Layer 2에서 서비스 IP 주소를 알리기 위해 ARP를 사용할 수 있도록 허용합니다.
- l2 policy sample

```yaml
# layer2-policy.yaml
---
apiVersion: "cilium.io/v2alpha1"
kind: CiliumL2AnnouncementPolicy
metadata:
  name: l2announcement-policy
spec:
  serviceSelector:
    matchLabels:
      org: empire
  nodeSelector:
    matchExpressions:
      - key: node-role.kubernetes.io/control-plane
        operator: DoesNotExist
  interfaces:
    - ^eth[0-9]+
  externalIPs: true
  loadBalancerIPs: true
```

### 탈출 게이트웨이

- 많은 엔터프라이즈 환경에서 Kubernetes에 호스팅된 애플리케이션은 Kubernetes 클러스터 외부에 있는 워크로드와 통신해야 하며, 이는 연결 제약 및 보안 시행의 적용을 받습니다. 이러한 네트워크의 특성으로 인해 기존 방화벽은 일반적으로 정적 IP 주소(또는 최소한 IP 범위)에 의존합니다. 이로 인해 노드 수가 다양하고 때로는 동적인 Kubernetes 클러스터를 이러한 네트워크에 통합하기 어려울 수 있습니다.
- Cilium의 Egress Gateway 기능은 이를 변경하여 포드가 외부 세계에 도달하기 위해 어떤 노드를 사용해야 하는지 지정할 수 있도록 합니다. 이러한 포드의 트래픽은 노드의 IP 주소로 소스 NAT되고 예측 가능한 IP로 외부 방화벽에 도달하여 방화벽이 포드에 올바른 정책을 시행할 수 있도록 합니다.
- egress gateway yaml sample

```bash
apiVersion: cilium.io/v2
kind: CiliumEgressGatewayPolicy
metadata:
  name: remote-outpost
spec:
  destinationCIDRs:
    - "10.0.4.0/24"
  selectors:
    - podSelector:
        matchLabels:
          org: empire
  egressGateway:
    nodeSelector:
      matchLabels:
        egress-gw: 'true'
    interface: net1
```

#### 2. 데이터 관리

- 커널 내에서 실행되기 때문에 매우 빠르고 효율적으로 데이터 접근 가능

- 각 맵에는 저장할 수 있는 데이터의 양에 제한이 있음

- eBPF 프로그램은 BPF 맵에 데이터를 읽고 쓰는 작업을 수행

- 컨테이너 ID를 기반으로 라우팅 기능 지원

- HTTP, gRPC, Kafka와 같은 API 프로토콜을 구문 분석

![alt text](./_image/cilium_rule_base_triffic_flow.png)

### Cilium 구조

### Cilium 리소스 목록

#### 1. Cilium으로 배포되는 리소스

| Resource   | Name            | Description                                                                                |
| :--------- | :-------------- | :----------------------------------------------------------------------------------------- |
| daemonset  | cilium-envoy    | 트래픽 관리 (L7 트래픽 처리, 로드밸런싱, rate limiting, circuit breaking 등)               |
| daemonset  | cilium          | Cilium Agent로서 네트워크 정책 적용, 파드 간 네트워킹, eBPF 프로그램 로드 등 수행          |
| deployment | cilium-operator | Clustor 전체 Cilium 관리, CRD 처리, 네트워크 정책 검증, IPAM 관리                          |
| deployment | hubble-relay    | Hubble 모니터링 데이터 수집/중계(전달), Hubble CLI 및 UI 통신 브릿지 역할 수행             |
| deployment | hubble-ui       | 모니터링 대시보드(메트릭 정보, 네트워크 플로우 정보, 네트워크 정책, 트러블 슈팅 화면) 제공 |

#### 2. Cilium Custom Resource Definition (CRD)

- CRD 종류

| Name                             | Description                                                                        | Default |
| :------------------------------- | :--------------------------------------------------------------------------------- | :-----: |
| ciliumcidrgroups                 | CIDR(범위) 그룹을 정의하여 네트워크 정책에서 IP 주소의 범위를 관리하는데 사용한다. |         |
| ciliumclusterwidenetworkpolicies | 클러스터 전체에 적용되는 네트워크 정책 생성에 사용한다.                            |         |
| ciliumnetworkpolicies            | 개별 리소스에 적용되는 네트워크 정책 생성에 사용한다.                              |         |
| ciliumendpoints                  | Cilium이 관리하는 엔드포인트(Pod, 서비스)의 정보를 관리하는데 사용한다.            |    ○    |
| ciliumexternalworkloads(beta)    | Kubernetes 클러스터 외부의 워크로드(VM 등)를 관리(액세스 제어)하는데 사용          |         |
| ciliumidentities                 | Pod의 레이블, ID을 관리한다. (동일한 라벨을 가진 PoD는 같은 ID 부여)               |    ○    |
| ciliuml2announcementpolicies     | 서비스의 ExternalIP/LBIP에 대한 ARP 쿼리에 응답하도록 설정하는데 사용한다.         |         |
| ciliumloadbalancerippools        | 로드 밸런서타입 서비스의 IP 풀을 정의하는데 사용한다.                              |         |
| ciliumnodeconfigs                | Cilium 노드의 설정을 정의하는데 사용한다.                                          |         |
| ciliumnodes                      | Cilium에서 관리하는 노드의 정보를 관리한다.                                        |    ○    |
| ciliumpodippools                 | Pod에 할당되는 IP 주소 풀을 관리한다.                                              |         |

### cilium ipam - kubernetes scope mode

- `Kubernetes Controller Manager`에 할당된 CIDR 확인

```bash
$ kubectl describe pod -n kube-system kube-controller-manager-control | grep -A10 Command
    Command:
      kube-controller-manager
      --allocate-node-cidrs=true
      --authentication-kubeconfig=/etc/kubernetes/controller-manager.conf
      --authorization-kubeconfig=/etc/kubernetes/controller-manager.conf
      --bind-address=127.0.0.1
      --client-ca-file=/etc/kubernetes/pki/ca.crt
      --cluster-cidr=10.100.0.0/16
      --cluster-name=kubernetes
      --cluster-signing-cert-file=/etc/kubernetes/pki/ca.crt
      --cluster-signing-key-file=/etc/kubernetes/pki/ca.key
```

- cilium 설치

```bash
helm install cilium cilium/cilium --version 1.17.5 --namespace kube-system \
--set k8sServiceHost=10.0.0.10 --set k8sServicePort=6443 \
--set ipv4NativeRoutingCIDR=10.0.0.10/16 \
--set kubeProxyReplacement=true \
--set routingMode=native \
--set autoDirectNodeRoutes=true \
--set bpf.masquerade=true \
--set ipam.mode=kubernetes \          # IPAM 지정
--set k8s.requireIPv4PodCIDR=true \   # K8S Pod CIDR OPTION
--set installNoConntrackIptablesRules=true \
--set operator.replicas=1
```

- Cilium CLI 이용 IPAM mode 체크

```bash
$ cilium config view | grep ipam
ipam                                              kubernetes
```

- Cilium Node에 할당된 PodCIDR 체크

```bash
$ kubectl get ciliumnode node01 -o jsonpath='{.spec.ipam}'
{ "podCIDRs": ["10.100.1.0/24"], "pools": {} }
```

### Cilium 설정 및 정보 조회

#### 1. 기본 명령어 설정

- 마스터 노드의 NAME을 CILIUMPOD0 변수에 저장한다.

- cilium agent 내부에서 실행 가능한 cilium 명령어를 쓸 수 있도록 c0 alias를 생성한다.

```bash
# /etc/profile
export CILIUMPOD0=$(kubectl get -l k8s-app=cilium pods -n kube-system --field-selector spec.nodeName=control  -o jsonpath='{.items[0].metadata.name}')
export CILIUMPOD1=$(kubectl get -l k8s-app=cilium pods -n kube-system --field-selector spec.nodeName=node01  -o jsonpath='{.items[0].metadata.name}')
export CILIUMPOD2=$(kubectl get -l k8s-app=cilium pods -n kube-system --field-selector spec.nodeName=node02  -o jsonpath='{.items[0].metadata.name}')
alias c0="kubectl exec -it $CILIUMPOD0 -n kube-system -c cilium-agent -- cilium"
alias c1="kubectl exec -it $CILIUMPOD1 -n kube-system -c cilium-agent -- cilium"
alias c2="kubectl exec -it $CILIUMPOD2 -n kube-system -c cilium-agent -- cilium"
alias c0bpf="kubectl exec -it $CILIUMPOD0 -n kube-system -c cilium-agent -- bpftool"
alias c1bpf="kubectl exec -it $CILIUMPOD1 -n kube-system -c cilium-agent -- bpftool"
alias c2bpf="kubectl exec -it $CILIUMPOD2 -n kube-system -c cilium-agent -- bpftool"
```

```bash
source /etc/profile
c0 status --verbose
```

#### 2. Cilium Nodes(CRD) 정보 조회

- CILIUMINTERNALIP : Cilium에서 사용되는 내부 IP 주소로 Cilium이 네트워크 기능을 제공하기 위해 각 노드에 할당한 IP 주소다.

- INTERNALIP : 노드의 실제 내부 IP 주소로 Pod간 통신에 사용된다.

```bash
$ kubectl get ciliumnodes
NAME      CILIUMINTERNALIP   INTERNALIP   AGE
control   10.100.0.211       10.0.0.10    40h
node01    10.100.1.118       10.0.0.11    40h
node02    10.100.2.249       10.0.0.12    40h
```

- `CILIUMINTERNALIP는` 실제로 각 노드에서 Proxy로 사용되는 IP로 각 노드에서 실행되고 있는 cilium agent 설정을 살펴보면 해당 IP를 볼 수 있다.

```bash
$ c0 status | grep "Proxy Status"
Proxy Status:            OK, ip 10.100.0.211, 0 redirects active on ports 10000-20000, Envoy: external
```

- 노드의 호스트의 인터페이스 목록을 보면 cilium이 할당한 `cilium_host` 인터페이스에 `CILIUMINTERNALIP가` 할당되어 있는 것을 볼 수 있다.

```bash
$ ip -br -c addr
lo                      UNKNOWN        127.0.0.1/8 ::1/128
enp0s3                  UP             10.0.0.10/16 fe80::a00:27ff:fe64:aed2/64
cilium_net@cilium_host  UP             fe80::80d0:f8ff:fe6c:ecd1/64
cilium_host@cilium_net  UP             10.100.0.211/32 fe80::a497:b5ff:fe42:67af/64
lxc_health@if5          UP             fe80::38d8:e1ff:fe8e:59eb/64
```

#### 3. Cilium Endpoints(CRD) 정보 조회

3.1 Cilium Endpoints

- Cilium은 컨테이너에 IP 주소를 할당하는 IPAM 기능을 제공한다.

- (확인필요) 여러 개의 Application 컨테이너가 IP 주소를 공유할 수 있는데 같은 IP 주소를 가진 컨테이너 그룹의 관리를 위해 Endpoint

- `c0 endpoint list` 명령으로 조회 시 ENPOINT 정보와 POLICY, IDENTITY, LABELS, IP를 확인할 수 있다.

  - ENDPOINT : 엔드포인트의 고유 ID

  - IDENTITY : Cilium에서 할당한 보안 식별자(SECURITY IDENTITY)로 정책 적용 및 트래픽 필터링에 사용된다.

    - IDENTITY는 cilium이 각 ip에 부여하는 보안 정체성이다.

    - IDENTITY는 엔드포인트 간의 연결을 보장하는 역할을 수행한다.

    - IDENTITY는 파드, 컨테이너가 가지고 있는 레이블에 의해 정의된다.

    - 같은 레이블을 가진 모든 엔프로인트는 같은 정체성을 공유하게 된다.

    - IDENTITY가 같은 엔드포인트에게는 개별 적으로 보안 정책을 적용하지 않고 IDENTITY에 보안 정책을 적용해 동일한 정책을 적용할 수 있다.

```bash
$ c0 endpoint list
ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                                   IPv6   IPv4           STATUS
           ENFORCEMENT        ENFORCEMENT
331        Disabled           Disabled          4          reserved:health                                                      10.100.0.148   ready
2324       Disabled           Disabled          1          k8s:node-role.kubernetes.io/control-plane                                           ready
                                                           k8s:node.kubernetes.io/exclude-from-external-load-balancers
                                                           reserved:host

$ c1 endpoint list
ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                                                  IPv6   IPv4           STATUS
           ENFORCEMENT        ENFORCEMENT
31         Enabled            Disabled          55374      k8s:app.kubernetes.io/name=argocd-dex-server                                        10.100.1.185   ready
                                                           k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=argocd
                                                           k8s:io.cilium.k8s.policy.cluster=default
                                                           k8s:io.cilium.k8s.policy.serviceaccount=argocd-dex-server
                                                           k8s:io.kubernetes.pod.namespace=argocd
...
2991       Disabled           Disabled          46404      k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=kube-system          10.100.1.209   ready
                                                           k8s:io.cilium.k8s.policy.cluster=default
                                                           k8s:io.cilium.k8s.policy.serviceaccount=coredns
                                                           k8s:io.kubernetes.pod.namespace=kube-system
                                                           k8s:k8s-app=kube-dns
3424       Disabled           Disabled          46404      k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=kube-system          10.100.1.200   ready
                                                           k8s:io.cilium.k8s.policy.cluster=default
                                                           k8s:io.cilium.k8s.policy.serviceaccount=coredns
                                                           k8s:io.kubernetes.pod.namespace=kube-system
                                                           k8s:k8s-app=kube-dns
```

- cilium bpf에서 관리되는 Endpoint 정보를 보면 ENDPOINT ID와 SECRUTIRY ID를 확인할 수 있다.

```bash
$ c0 bpf endpoint list
IP ADDRESS       LOCAL ENDPOINT   INFO
10.0.0.10:0      (localhost)
10.100.0.211:0   (localhost)
10.100.0.148:0   id=331   sec_id=4     flags=0x0000 ifindex=6   mac=BE:EE:B4:F3:41:63 nodemac=3A:D8:E1:8E:59:EB parent_ifindex=0

$ c1 bpf endpoint list
IP ADDRESS       LOCAL ENDPOINT INFO
10.100.1.200:0   id=3424  sec_id=46404 flags=0x0000 ifindex=10  mac=36:BC:DE:4A:B7:B9 nodemac=4A:B2:F8:A2:6C:65 parent_ifindex=0
10.100.1.119:0   id=158   sec_id=4     flags=0x0000 ifindex=22  mac=42:61:90:C5:7B:DF nodemac=82:00:61:A2:46:1E parent_ifindex=0
10.100.1.209:0   id=2991  sec_id=46404 flags=0x0000 ifindex=12  mac=7A:5E:4C:41:D1:F2 nodemac=0A:9B:88:4F:A7:4F parent_ifindex=0
10.100.1.28:0    id=292   sec_id=8161  flags=0x0000 ifindex=18  mac=86:7E:0B:05:F3:5F nodemac=5E:36:2B:8C:F1:FA parent_ifindex=0
10.0.0.11:0      (localhost)
10.100.1.91:0    id=104   sec_id=5906  flags=0x0000 ifindex=14  mac=F6:1F:11:C9:2E:2B nodemac=72:22:1E:80:7E:55 parent_ifindex=0
10.100.1.220:0   id=1299  sec_id=7784  flags=0x0000 ifindex=6   mac=BA:96:ED:3F:5A:BC nodemac=0E:7C:C2:2A:D7:DA parent_ifindex=0
10.100.1.118:0   (localhost)
10.100.1.185:0   id=31    sec_id=55374 flags=0x0000 ifindex=20  mac=1E:B9:7E:C0:DD:50 nodemac=9E:44:43:D2:97:1B parent_ifindex=0
10.100.1.36:0    id=38    sec_id=4760  flags=0x0000 ifindex=16  mac=1A:86:D3:21:8B:AB nodemac=0E:D8:21:10:BF:A2 parent_ifindex=0
```

3.2 Cilium Endpoints(CRD) 정보 조회

- `ciliumendpoints` CRD 명칭으로 정보를 검색하면 위에서 확인한 `SECURITY IDENTITY` 정보를 확인할 수 있다.

- SECURITY IDENTITY : Cilium에서 할당한 보안 식별자로 정책 적용 및 트래픽 필터링에 사용된다.

- IPV4 : 실제 Pod에 할당된 IP다.

```bash
$ kubectl get ciliumendpoints -A
NAMESPACE       NAME                                                SECURITY IDENTITY   ENDPOINT STATE   IPV4           IPV6
argocd          argocd-application-controller-0                     7784                ready            10.100.1.220
argocd          argocd-applicationset-controller-655cc58ff8-b8nsr   32701               ready            10.100.2.21
argocd          argocd-dex-server-7d9dfb4fb8-8mmc9                  55374               ready            10.100.1.185
argocd          argocd-notifications-controller-6c6848bc4c-tsfc2    9606                ready            10.100.2.122
argocd          argocd-redis-656c79549c-xvdrj                       8161                ready            10.100.1.28
argocd          argocd-repo-server-856b768fd9-k7h5j                 4329                ready            10.100.2.32
argocd          argocd-server-99c485944-fsbht                       30057               ready            10.100.2.222
ingress-nginx   ingress-nginx-controller-7bd4bbb674-lk679           49866               ready            10.100.2.188
kube-system     coredns-668d6bf9bc-jqkqh                            46404               ready            10.100.1.209
kube-system     coredns-668d6bf9bc-lv52b                            46404               ready            10.100.1.200
kube-system     hubble-relay-646f5c4cb7-9bjk7                       4760                ready            10.100.1.36
kube-system     hubble-ui-76d4965bb6-zbvb7                          5906                ready            10.100.1.91
```

#### 4. Cilium Identites 에서 관리하는 정보

- Cilium Endpoints에서 조회된 `SECURITY IDENTITY` 값이 `Identites`에서 확인 된다.

```bash
$ kubectl get ciliumidentities
NAME    NAMESPACE       AGE
30057   argocd          40h
32701   argocd          40h
4329    argocd          40h
46404   kube-system     40h
4760    kube-system     40h
49866   ingress-nginx   40h
55374   argocd          40h
5906    kube-system     40h
7784    argocd          40h
8161    argocd          40h
9606    argocd          40h
```

#### 5. KubeProxyReplacement 설정

- True : kube-proxy를 대체해서 cilium이 서비스 트래픽을 처리하는 설정

- enp0s3 : Cilium Agent가 사용 중인 네트워크 인터페이스 정보

- 10.0.0.10 : 인터페이스에 할당된 IP 주소

- Direct Routing : 클러스터 내의 서비스 트래픽이 직접 파드에 전달되는 설정, Cilium이 BPF를 사용하여 패킷을 직접 필터링하고 처리

```bash
$ c0 status | grep KubeProxyReplacement
KubeProxyReplacement:   True   [enp0s3   10.0.0.10 fe80::a00:27ff:fe64:aed2 (Direct Routing)]
```

#### 6. Routing 설정

- Network : Native

  - Kubernetes 클러스터 내에서 사용하는 네트워크 라우팅 방식

  - Cilium이 Kubernetes의 네트워킹 스택과 통합되어 IP 패킷을 직접 처리하고, Kubernetes API를 통해 서비스를 관리하는 방식

- Host : BPF

  - Cilium이 호스트 시스템에서 패킷을 처리하는 방법

```bash
$ c0 status | grep Routing
Routing:                Network: Native   Host: BPF
```

#### 7. Masquerading 설정

- BPF : BPF를 이용해서 패킷 출발지 IP를 변경하는데 사용하는 설정

- enp0s3 : Cilium이 Masquerading을 적용하는 대상 인터페이스

- 10.0.0.0/16 : Masquerading을 적용되는 대상 CIDR

```bash
$ c0 status | grep Masquerading
Masquerading:           BPF   [enp0s3]   10.0.0.0/16 [IPv4: Enabled, IPv6: Disabled]
```

#### 8. Proxy Status 설정

- OK : Proxy 상태 정상

- ip 10.100.0.211 : Proxy 내부 IP 주소

- 0 redirects active on ports 10000-20000 : 10000번에서 20000번 포트 간에 활성화된 리다이렉트가 없음

- Envoy external : Envoy 프록시가 외부 환경에서 실행되도록 설정되어 있음

```bash
$ c0 status | grep "Proxy Status"
Proxy Status:            OK, ip 10.100.0.211, 0 redirects active on ports 10000-20000, Envoy: external
```

#### 9. BPF Maps

- BPF Maps : Cilium이 BPF를 활용하여 작업하면서 네트워크 트래픽, 상태 정보, 라우팅 정보 등 여러 정보를 저장하는 데 사용한다.

- Dynamic Sizing On : BPF 맵의 크기가 동적으로 조정

- Ratio: 0.002500 : BPF 맵의 최적화 비율

```bash
$ c0 status --verbose | grep BPF
BPF Maps:   dynamic sizing: on (ratio: 0.002500)
```

#### 10. Cilium Service List

- Frontend : 클라이언트가 접근하는 서비스의 IP 주소와 포트

- Service Type : Cluster IP, NodePort, LoadBalancer

- Backend : 실제 트래픽이 전달되는 백엔드 IP 주소와 포트 (서비스에 직접 연결되어 있는 Endpoint(Pod) 정보)

```bash
$ c0 service list
ID   Frontend                  Service Type   Backend
1    10.200.59.40:7000/TCP     ClusterIP      1 => 10.100.2.21:7000/TCP (active)
2    10.200.59.40:8080/TCP     ClusterIP      1 => 10.100.2.21:8080/TCP (active)
3    10.200.209.77:5556/TCP    ClusterIP      1 => 10.100.1.185:5556/TCP (active)
4    10.200.209.77:5557/TCP    ClusterIP      1 => 10.100.1.185:5557/TCP (active)
5    10.200.209.77:5558/TCP    ClusterIP      1 => 10.100.1.185:5558/TCP (active)
6    10.200.11.27:8082/TCP     ClusterIP      1 => 10.100.1.220:8082/TCP (active)
7    10.200.215.80:9001/TCP    ClusterIP      1 => 10.100.2.122:9001/TCP (active)
8    10.200.120.124:6379/TCP   ClusterIP      1 => 10.100.1.28:6379/TCP (active)
9    10.200.54.249:8081/TCP    ClusterIP      1 => 10.100.2.32:8081/TCP (active)
10   10.200.54.249:8084/TCP    ClusterIP      1 => 10.100.2.32:8084/TCP (active)
11   10.200.158.229:80/TCP     ClusterIP      1 => 10.100.2.222:8080/TCP (active)
12   10.200.158.229:443/TCP    ClusterIP      1 => 10.100.2.222:8080/TCP (active)
13   10.0.250.0:80/TCP         LoadBalancer   1 => 10.100.2.222:8080/TCP (active)
14   10.0.250.0:443/TCP        LoadBalancer   1 => 10.100.2.222:8080/TCP (active)
...
```

- `kubectl get svc` 서비스 목록 조회 시 실제 할당된 IP 정보 조회 가능

```bash
$ kubectl get svc -A | grep argocd-server
argocd          argocd-server                             LoadBalancer   10.200.158.229   10.0.250.0    80:31690/TCP,443:30195/TCP   2d8h
```

- `BACKEND ADDRESS`는 LB 타입 서비스가 트래픽을 받은 후 전달할 TARGET POD의 IP다.

```bash
$ kubectl get po -n argocd -o wide | grep 10.100.2.222
argocd-server-99c485944-fsbht                       1/1     Running   1 (2d4h ago)   2d8h   10.100.2.222   node02   <none>           <none>
```

#### 11. Cilium이 관리하는 로드밸런싱 정보

- SERVICE ADDRESS : 클라이언트가 접근하는 서비스의 IP 주소와 포트

- BACKEND ADDRESS : 실제 트래픽이 전달되는 백엔드 IP 주소와 포트 (서비스에 직접 연결되어 있는 Endpoint(Pod) 정보)

- (REVNAT_ID) : 해당 주소의 고유 식별자 → `c0 bpf lb list --revnat` 조회 시 ID 값 확인 가능

- 서비스 유형 :

  - [ClusterIP, non-routable] : 클러스터 내부에서만 접근 가능한 서비스, 외부에서 접근 제한

  - [NodePort] : 클러스터 외부에서도 접근 가능한 서비스, 클러스터 내 모든 노드에서 트래픽 수신 가능

  - [NodePort, Local, two-scopes, non-routable] : 해당 노드에 있는 파드로만 트래픽 전달

  - [LoadBalancer] : 클러스터 외부에서도 접근 가능한 서비스, 클러스터 내 모든 노드의 파드로 트래픽 분산

  - [LoadBalancer, Local, two-scopes] : 로드밸런서가 트래픽을 보낸 해당 노드의 파드로만 전달

```bash
c0 bpf lb list
SERVICE ADDRESS               BACKEND ADDRESS (REVNAT_ID) (SLOT)
10.200.215.80:9001/TCP (1)    10.100.2.122:9001/TCP (7) (1)
10.200.201.226:443/TCP (1)    10.100.2.188:443/TCP (23) (1)
10.200.54.249:8081/TCP (1)    10.100.2.32:8081/TCP (9) (1)
10.200.209.77:5557/TCP (0)    0.0.0.0:0 (4) (0) [ClusterIP, non-routable]
10.200.54.249:8084/TCP (1)    10.100.2.32:8084/TCP (10) (1)
0.0.0.0:32179/TCP/i (0)       0.0.0.0:0 (31) (0) [NodePort, Local, two-scopes, non-routable]
0.0.0.0:32179/TCP (0)         0.0.0.0:0 (30) (0) [NodePort, Local, two-scopes, non-routable]
10.200.0.10:53/UDP (1)        10.100.1.209:53/UDP (41) (1)
10.200.120.124:6379/TCP (1)   10.100.1.28:6379/TCP (8) (1)
10.200.126.139:80/TCP (1)     10.100.1.91:8081/TCP (38) (1)
10.0.0.10:32179/TCP/i (1)     10.100.2.188:443/TCP (29) (1)
10.0.250.1:443/TCP (0)        0.0.0.0:0 (26) (0) [LoadBalancer, Local, two-scopes]
```

#### 12. Cilium Reverse NAT

- Cilium은 외부에서 클러스터 내의 서비스로 요청이 들어올 때 Reverse NAT를 사용하여 요청을 적절한 Pod로 전달

- 외부에서 들어오는 요청을 클러스터 내의 특정 Pod로 전달하는 기능

- `c0 bpf lb list --revnat` 명령으로 NAT 설정 목록을 확인할 수 있다.

```bash
$ c0 bpf lb list --revnat
ID   BACKEND ADDRESS (REVNAT_ID) (SLOT)
35   0.0.0.0:31181
20   10.200.0.1:443
16   0.0.0.0:31690
22   10.200.201.226:80
19   10.200.245.138:8083
...
```

- 앞에서 Cilium Service List에서 확인한 argocd-server LB IP 값 확인 가능

```bash
$ c0 bpf lb list --revnat | grep 10.0.250.0
14   10.0.250.0:443
13   10.0.250.0:80
```

## eBPF의 Kernel Hook Point

- System Call Hooks(BPF 시스템 호출): 네트워크 관련 시스템 호출에 eBPF 프로그램을 연결하여 시스템 호출의 동작을 모니터링하거나 수정합니다.

- Socket Hooks(Sockmap 및 Sockops): 소켓 레이어에서 소켓 연산과 데이터 스트림을 가로채어 효율적인 데이터 처리를 가능하게 합니다.

- cGroup Hooks: 컨트롤 그룹(cGroups)에 eBPF 프로그램을 연결하여 프로세스 그룹 단위로 네트워크 트래픽을 제어하고 정책을 적용합니다.

- TC(Traffic Control) Hooks: 트래픽 컨트롤 서브시스템의 인그레스(ingress)와 이그레스(egress)에서 패킷을 필터링하거나 수정하기 위해 eBPF 프로그램을 연결합니다.

- XDP(eXpress Data Path): 네트워크 드라이버 레벨에서 패킷을 처리하여 커널 스택에 진입하기 전에 고성능 패킷 필터링 및 조작을 수행합니다.

![alt text](./_image/ebpf_kernel_hook_point.png)

---

Native Routing Mode 통신 테스트

- 통신 테스트용 curl 파드 배포

```yaml
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: curl-pod
  labels:
    app: curl
spec:
  nodeName: cilium-ctr
  containers:
  - name: curl
    image: nicolaka/netshoot
    command: ["tail"]
    args: ["-f", "/dev/null"]
  terminationGracePeriodSeconds: 0
EOF
```

- 통신 테스트용 web 파드 배포

```yaml
cat << EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webpod
spec:
  replicas: 2
  selector:
    matchLabels:
      app: webpod
  template:
    metadata:
      labels:
        app: webpod
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - sample-app
            topologyKey: "kubernetes.io/hostname"
      containers:
      - name: webpod
        image: traefik/whoami
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: webpod
  labels:
    app: webpod
spec:
  selector:
    app: webpod
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
  type: ClusterIP
EOF
```

```bash
$ ip route
default via 10.0.0.1 dev enp0s3 proto static
10.0.0.0/16 dev enp0s3 proto kernel scope link src 10.0.0.10
10.100.0.148 dev lxc_health proto kernel scope link
10.100.1.0/24 via 10.0.0.11 dev enp0s3 proto kernel
10.100.2.0/24 via 10.0.0.12 dev enp0s3 proto kernel

$ c0 status | grep IPAM   # 1번 노드 (control)
IPAM:                    IPv4: 2/254 allocated from 10.100.0.0/24,
$ c1 status | grep IPAM   # 2번 노드 (node01)
IPAM:                    IPv4: 9/254 allocated from 10.100.1.0/24,
$ c2 status | grep IPAM   # 3번 노드 (node02)
IPAM:                    IPv4: 7/254 allocated from 10.100.2.0/24,
```

- Native Routing이 활성화 되면 Cilium이 자동으로 리눅스 커널의 IP Forwarding 기능(net.ipv4.ip_forward 설정)을 활성화한다.

  ```bash
  sysctl net.ipv4.ip_forward
  net.ipv4.ip_forward = 1
  ```

![alt text](./_image/native_mode_routing.png)

또, Cilium Agent를 이용해도 노드에 연결된 PodCIDR을 확인할 수 있는데, 전체 254개의 IP 중 9개의 IP를 사용하고 있는 것을 확인할 수 있다. `--verbose` 옵션을 추가후 `Allocated` 필드를 확인하면 어떤 리소스들이 할당되어 있는지도 확인할 수 있다. Cilium은 Default로 노드마다 Router(cilium_host nic)와 health용 ip 각 1개를 할당한다.

```bash
$ c1 status | grep IPAM
IPAM:                    IPv4: 9/254 allocated from 10.100.1.0/24,
```

```bash
c1 status --verbose | grep -A10 "Allocated"
Allocated addresses:
  10.100.1.118 (router)
  10.100.1.119 (health)
  10.100.1.185 (argocd/argocd-dex-server-7d9dfb4fb8-8mmc9 [restored])
  10.100.1.200 (kube-system/coredns-668d6bf9bc-lv52b [restored])
  10.100.1.209 (kube-system/coredns-668d6bf9bc-jqkqh [restored])
  10.100.1.220 (argocd/argocd-application-controller-0 [restored])
  10.100.1.28 (argocd/argocd-redis-656c79549c-xvdrj [restored])
  10.100.1.36 (kube-system/hubble-relay-646f5c4cb7-9bjk7 [restored])
  10.100.1.91 (kube-system/hubble-ui-76d4965bb6-zbvb7 [restored])
IPv4 BIG TCP:           Disabled
```
