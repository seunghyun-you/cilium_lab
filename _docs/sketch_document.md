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
