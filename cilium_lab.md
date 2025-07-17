### LAB URL

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
