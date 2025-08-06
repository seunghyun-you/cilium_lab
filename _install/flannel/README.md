### Flannel CNI 설치

#### flannel helm repo 등록

```bash
# Needs manual creation of namespace to avoid helm error
kubectl create ns kube-flannel
kubectl label --overwrite ns kube-flannel pod-security.kubernetes.io/enforce=privileged

helm repo add flannel https://flannel-io.github.io/flannel/
helm repo list
helm search repo flannel
helm show values flannel/flannel
```

#### flannel valuse.yaml 파일 설정

```bash
cat << EOF > flannel-values.yaml
podCidr: "10.244.0.0/16"

flannel:
  args:
  - "--ip-masq"
  - "--kube-subnet-mgr"
  - "--iface=eth1"
EOF
```

#### flannel 설치

```bash
helm install flannel --namespace kube-flannel flannel/flannel -f flannel-values.yaml
helm list -A
```

#### flannel 네트워크 정보

- flannel 설치 전 interface 정보

```bash
ip -c link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:6b:69:c9 brd ff:ff:ff:ff:ff:ff
    altname enp0s3
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:04:c9:d0 brd ff:ff:ff:ff:ff:ff
    altname enp0s8
```

- flannel 설치 후 interface 정보

```bash
ip -c link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:6b:69:c9 brd ff:ff:ff:ff:ff:ff
    altname enp0s3
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:04:c9:d0 brd ff:ff:ff:ff:ff:ff
    altname enp0s8
4: flannel.1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UNKNOWN mode DEFAULT group default
    link/ether 62:21:5d:f5:87:2c brd ff:ff:ff:ff:ff:ff
```

- flannel 설치 전 라우팅 정보

```bash
ip -c route
default via 10.0.2.2 dev eth0 proto dhcp src 10.0.2.15 metric 100
10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15 metric 100
10.0.2.2 dev eth0 proto dhcp scope link src 10.0.2.15 metric 100
10.0.2.3 dev eth0 proto dhcp scope link src 10.0.2.15 metric 100
192.168.20.0/24 dev eth1 proto kernel scope link src 192.168.20.100
```

- flannel 설치 후 라우팅 정보

```bash
ip -c route
default via 10.0.2.2 dev eth0 proto dhcp src 10.0.2.15 metric 100
10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15 metric 100
10.0.2.2 dev eth0 proto dhcp scope link src 10.0.2.15 metric 100
10.0.2.3 dev eth0 proto dhcp scope link src 10.0.2.15 metric 100
10.244.1.0/24 via 10.244.1.0 dev flannel.1 onlink
10.244.2.0/24 via 10.244.2.0 dev flannel.1 onlink
192.168.20.0/24 dev eth1 proto kernel scope link src 192.168.20.100
```

- flannel 설치 전 iptable nat 테이블

```bash
iptabless -t nat -S
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:KUBE-KUBELET-CANARY - [0:0]
:KUBE-MARK-MASQ - [0:0]
:KUBE-NODEPORTS - [0:0]
:KUBE-POSTROUTING - [0:0]
:KUBE-PROXY-CANARY - [0:0]
:KUBE-SEP-U7HH75UFG3U5VGYY - [0:0]
:KUBE-SERVICES - [0:0]
:KUBE-SVC-NPX46M4PTMTKRN6Y - [0:0]
-A PREROUTING -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
-A OUTPUT -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
-A POSTROUTING -m comment --comment "kubernetes postrouting rules" -j KUBE-POSTROUTING
-A KUBE-MARK-MASQ -j MARK --set-xmark 0x4000/0x4000
-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
-A KUBE-POSTROUTING -j MARK --set-xmark 0x4000/0x0
-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE --random-fully
-A KUBE-SEP-U7HH75UFG3U5VGYY -s 192.168.20.100/32 -m comment --comment "default/kubernetes:https" -j KUBE-MARK-MASQ
-A KUBE-SEP-U7HH75UFG3U5VGYY -p tcp -m comment --comment "default/kubernetes:https" -m tcp -j DNAT --to-destination 192.168.20.100:6443
-A KUBE-SERVICES -d 10.96.0.1/32 -p tcp -m comment --comment "default/kubernetes:https cluster IP" -m tcp --dport 443 -j KUBE-SVC-NPX46M4PTMTKRN6Y
-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
-A KUBE-SVC-NPX46M4PTMTKRN6Y ! -s 10.244.0.0/16 -d 10.96.0.1/32 -p tcp -m comment --comment "default/kubernetes:https cluster IP" -m tcp --dport 443 -j KUBE-MARK-MASQ
-A KUBE-SVC-NPX46M4PTMTKRN6Y -m comment --comment "default/kubernetes:https -> 192.168.20.100:6443" -j KUBE-SEP-U7HH75UFG3U5VGYY
COMMIT
# Completed on Mon Jul 14 13:12:21 2025
```

- flannel 설치 후 iptable nat 테이블

```bash
iptables -t nat -S
-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N FLANNEL-POSTRTG
-N KUBE-KUBELET-CANARY
-N KUBE-MARK-MASQ
-N KUBE-NODEPORTS
-N KUBE-POSTROUTING
-N KUBE-PROXY-CANARY
-N KUBE-SEP-CLAGU7VMF4VCXE4X
-N KUBE-SEP-DLP2S2N3HX5UKLVP
-N KUBE-SEP-H7FN6LU3RSH6CC2T
-N KUBE-SEP-TCIZBYBD3WWXNWF5
-N KUBE-SEP-TFTZVOJFQDTMM5AB
-N KUBE-SEP-U7HH75UFG3U5VGYY
-N KUBE-SEP-ZHICQ2ODADGCY7DS
-N KUBE-SERVICES
-N KUBE-SVC-ERIFXISQEP7F7OF4
-N KUBE-SVC-JD5MR3NA4I4DYORP
-N KUBE-SVC-NPX46M4PTMTKRN6Y
-N KUBE-SVC-TCOU7JCQXEZGVUNU
-A PREROUTING -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
-A OUTPUT -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
-A POSTROUTING -m comment --comment "kubernetes postrouting rules" -j KUBE-POSTROUTING
-A POSTROUTING -m comment --comment "flanneld masq" -j FLANNEL-POSTRTG
-A FLANNEL-POSTRTG -m mark --mark 0x4000/0x4000 -m comment --comment "flanneld masq" -j RETURN
-A FLANNEL-POSTRTG -s 10.244.0.0/24 -d 10.244.0.0/16 -m comment --comment "flanneld masq" -j RETURN
-A FLANNEL-POSTRTG -s 10.244.0.0/16 -d 10.244.0.0/24 -m comment --comment "flanneld masq" -j RETURN
-A FLANNEL-POSTRTG ! -s 10.244.0.0/16 -d 10.244.0.0/24 -m comment --comment "flanneld masq" -j RETURN
-A FLANNEL-POSTRTG -s 10.244.0.0/16 ! -d 224.0.0.0/4 -m comment --comment "flanneld masq" -j MASQUERADE --random-fully
-A FLANNEL-POSTRTG ! -s 10.244.0.0/16 -d 10.244.0.0/16 -m comment --comment "flanneld masq" -j MASQUERADE --random-fully
-A KUBE-MARK-MASQ -j MARK --set-xmark 0x4000/0x4000
-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
-A KUBE-POSTROUTING -j MARK --set-xmark 0x4000/0x0
-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE --random-fully
-A KUBE-SEP-CLAGU7VMF4VCXE4X -s 10.244.2.2/32 -m comment --comment "kube-system/kube-dns:metrics" -j KUBE-MARK-MASQ
-A KUBE-SEP-CLAGU7VMF4VCXE4X -p tcp -m comment --comment "kube-system/kube-dns:metrics" -m tcp -j DNAT --to-destination 10.244.2.2:9153
-A KUBE-SEP-DLP2S2N3HX5UKLVP -s 10.244.2.3/32 -m comment --comment "kube-system/kube-dns:dns-tcp" -j KUBE-MARK-MASQ
-A KUBE-SEP-DLP2S2N3HX5UKLVP -p tcp -m comment --comment "kube-system/kube-dns:dns-tcp" -m tcp -j DNAT --to-destination 10.244.2.3:53
-A KUBE-SEP-H7FN6LU3RSH6CC2T -s 10.244.2.2/32 -m comment --comment "kube-system/kube-dns:dns-tcp" -j KUBE-MARK-MASQ
-A KUBE-SEP-H7FN6LU3RSH6CC2T -p tcp -m comment --comment "kube-system/kube-dns:dns-tcp" -m tcp -j DNAT --to-destination 10.244.2.2:53
-A KUBE-SEP-TCIZBYBD3WWXNWF5 -s 10.244.2.2/32 -m comment --comment "kube-system/kube-dns:dns" -j KUBE-MARK-MASQ
-A KUBE-SEP-TCIZBYBD3WWXNWF5 -p udp -m comment --comment "kube-system/kube-dns:dns" -m udp -j DNAT --to-destination 10.244.2.2:53
-A KUBE-SEP-TFTZVOJFQDTMM5AB -s 10.244.2.3/32 -m comment --comment "kube-system/kube-dns:metrics" -j KUBE-MARK-MASQ
-A KUBE-SEP-TFTZVOJFQDTMM5AB -p tcp -m comment --comment "kube-system/kube-dns:metrics" -m tcp -j DNAT --to-destination 10.244.2.3:9153
-A KUBE-SEP-U7HH75UFG3U5VGYY -s 192.168.20.100/32 -m comment --comment "default/kubernetes:https" -j KUBE-MARK-MASQ
-A KUBE-SEP-U7HH75UFG3U5VGYY -p tcp -m comment --comment "default/kubernetes:https" -m tcp -j DNAT --to-destination 192.168.20.100:6443
-A KUBE-SEP-ZHICQ2ODADGCY7DS -s 10.244.2.3/32 -m comment --comment "kube-system/kube-dns:dns" -j KUBE-MARK-MASQ
-A KUBE-SEP-ZHICQ2ODADGCY7DS -p udp -m comment --comment "kube-system/kube-dns:dns" -m udp -j DNAT --to-destination 10.244.2.3:53
-A KUBE-SERVICES -d 10.96.0.1/32 -p tcp -m comment --comment "default/kubernetes:https cluster IP" -m tcp --dport 443 -j KUBE-SVC-NPX46M4PTMTKRN6Y
-A KUBE-SERVICES -d 10.96.0.10/32 -p udp -m comment --comment "kube-system/kube-dns:dns cluster IP" -m udp --dport 53 -j KUBE-SVC-TCOU7JCQXEZGVUNU
-A KUBE-SERVICES -d 10.96.0.10/32 -p tcp -m comment --comment "kube-system/kube-dns:dns-tcp cluster IP" -m tcp --dport 53 -j KUBE-SVC-ERIFXISQEP7F7OF4
-A KUBE-SERVICES -d 10.96.0.10/32 -p tcp -m comment --comment "kube-system/kube-dns:metrics cluster IP" -m tcp --dport 9153 -j KUBE-SVC-JD5MR3NA4I4DYORP
-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS
-A KUBE-SVC-ERIFXISQEP7F7OF4 ! -s 10.244.0.0/16 -d 10.96.0.10/32 -p tcp -m comment --comment "kube-system/kube-dns:dns-tcp cluster IP" -m tcp --dport 53 -j KUBE-MARK-MASQ
-A KUBE-SVC-ERIFXISQEP7F7OF4 -m comment --comment "kube-system/kube-dns:dns-tcp -> 10.244.2.2:53" -m statistic --mode random --probability 0.50000000000 -j KUBE-SEP-H7FN6LU3RSH6CC2T
-A KUBE-SVC-ERIFXISQEP7F7OF4 -m comment --comment "kube-system/kube-dns:dns-tcp -> 10.244.2.3:53" -j KUBE-SEP-DLP2S2N3HX5UKLVP
-A KUBE-SVC-JD5MR3NA4I4DYORP ! -s 10.244.0.0/16 -d 10.96.0.10/32 -p tcp -m comment --comment "kube-system/kube-dns:metrics cluster IP" -m tcp --dport 9153 -j KUBE-MARK-MASQ
-A KUBE-SVC-JD5MR3NA4I4DYORP -m comment --comment "kube-system/kube-dns:metrics -> 10.244.2.2:9153" -m statistic --mode random --probability 0.50000000000 -j KUBE-SEP-CLAGU7VMF4VCXE4X
-A KUBE-SVC-JD5MR3NA4I4DYORP -m comment --comment "kube-system/kube-dns:metrics -> 10.244.2.3:9153" -j KUBE-SEP-TFTZVOJFQDTMM5AB
-A KUBE-SVC-NPX46M4PTMTKRN6Y ! -s 10.244.0.0/16 -d 10.96.0.1/32 -p tcp -m comment --comment "default/kubernetes:https cluster IP" -m tcp --dport 443 -j KUBE-MARK-MASQ
-A KUBE-SVC-NPX46M4PTMTKRN6Y -m comment --comment "default/kubernetes:https -> 192.168.20.100:6443" -j KUBE-SEP-U7HH75UFG3U5VGYY
-A KUBE-SVC-TCOU7JCQXEZGVUNU ! -s 10.244.0.0/16 -d 10.96.0.10/32 -p udp -m comment --comment "kube-system/kube-dns:dns cluster IP" -m udp --dport 53 -j KUBE-MARK-MASQ
-A KUBE-SVC-TCOU7JCQXEZGVUNU -m comment --comment "kube-system/kube-dns:dns -> 10.244.2.2:53" -m statistic --mode random --probability 0.50000000000 -j KUBE-SEP-TCIZBYBD3WWXNWF5
-A KUBE-SVC-TCOU7JCQXEZGVUNU -m comment --comment "kube-system/kube-dns:dns -> 10.244.2.3:53" -j KUBE-SEP-ZHICQ2ODADGCY7DS
```

### flannel iptables 정보 분석

- iptables 정보에서 Service와 관련된 정보 검색

```bash
# kubectl get svc
NAME         TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)   AGE
kubernetes   ClusterIP   10.96.0.1      <none>        443/TCP   20d
webpod       ClusterIP   10.96.65.151   <none>        80/TCP    20d
# kubectl get po -owide
NAME                      READY   STATUS    RESTARTS      AGE   IP            NODE          NOMINATED NODE   READINESS GATES
curl-pod                  1/1     Running   6 (8h ago)    20d   10.244.0.4    flannel-ctr   <none>           <none>
webpod-697b545f57-7rsn9   1/1     Running   2 (28h ago)   20d   10.244.2.10   flannel-w2    <none>           <none>
webpod-697b545f57-85vnd   1/1     Running   3 (28h ago)   20d   10.244.1.5    flannel-w1    <none>           <none>
```

```bash
# iptables -nL -t nat
Chain KUBE-SVC-CNZCPOCNCNOROALA (1 references)
target     prot opt source               destination         
KUBE-MARK-MASQ  6    -- !10.244.0.0/16        10.96.65.151         /* default/webpod cluster IP */ tcp dpt:80
KUBE-SEP-4XUJ5ZCGHF23EWGS  0    --  0.0.0.0/0            0.0.0.0/0            /* default/webpod -> 10.244.1.5:80 */ statistic mode random probability 0.50000000000
KUBE-SEP-OLWBTI6CZXA3JRRX  0    --  0.0.0.0/0            0.0.0.0/0            /* default/webpod -> 10.244.2.10:80 */
```

- 10.244.0.0/16 외부 대역에서 들어 오는 트래픽 중 10.96.65.151:80 IP:PORT를 목적지로 오는 패킷이라면
- `10.244.1.5:80`,  `10.244.2.10:80` 목적지로 Masquerading 하여 RoundRobin 방식으로 라우팅하는 NAT 정책
- 이런 iptables 정보가 cilium에서는 보이지 않는다. eBPF를 통해서 처리되고 있기 때문이다.


### Flannel Sample APP 배포

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

```yaml
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: curl-pod
  labels:
    app: curl
spec:
  nodeName: flannel-ctr
  spec:
  containers:
    - name: curl
      image: alpine/curl
      command: ["sleep", "36000"]
EOF
```