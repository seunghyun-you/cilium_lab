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

### 2. 정보 조회
