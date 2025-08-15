- cilium 상태 확인

  ```bash
  cilium status
  cilium config view
  # Hubble 상태 확인
  cilium status | grep Hubble
  cilium config view | grep -i hubble
  ```

- cilium endpoint 정보 조회

  ```bash
  # 엔드포인트 기준 ID
  c0 identity list --endpoints

  # 엔드포인트 설정 확인 및 변경
  c0 endpoint config <엔트포인트ID>

  # 엔드포인트 상세 정보 확인
  c0 endpoint get <엔트포인트ID>

  # 엔드포인트 로그 확인
  c0 endpoint log <엔트포인트ID>
  ```


- cilium metric 수집 항목 리스트

  ```bash
  kubectl exec -n kube-system -c cilium-agent -it ds/cilium -- cilium-dbg metrics list
  ```

- cilium monitor 

  ```bash
  # 기본
  kubectl exec -n kube-system -c cilium-agent -it ds/cilium -- cilium-dbg monitor
  # 상세 
  kubectl exec -n kube-system -c cilium-agent -it ds/cilium -- cilium-dbg monitor -v -v
  # filter : endpoint id
  kubectl exec -n kube-system -c cilium-agent -it ds/cilium -- cilium-dbg monitor --related-to=<id>
  # filter : drop packet
  kubectl exec -n kube-system -c cilium-agent -it ds/cilium -- cilium-dbg monitor --type drop
  ```

- Hubble UI 접속 설정

  ```bash
  # Hubble 포트 정보 확인
  kubectl get svc,ep -n kube-system hubble-ui
  # 포트 정보만 변수에 저장
  PORT=$(kubectl get svc -n kube-system hubble-ui | grep -v PORT | awk '{print $5}' | cut -d: -f2 | cut -d/ -f1)
  # 웹 접속 주소 확인
  NODEIP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
  echo -e "http://$NODEIP:$PORT"
  ```

- Hubble trace 설정

  ```bash
  # Hubble Relay 설정
  cilium hubble port-forward&
  # 상태 확인
  hubble status
  # 전체 모니터링 
  hubble observe -f
  # protocol 지정
  hubble observe -f --protocol icmp 
  # identity 지정
  hubble observe -f --from-identity <IDENTITY_ID>
  # pod 지정
  hubble observe -f --pod <NAMESPACE/POD_NAME>
  ```
- 

  ```bash
  ```

- 

  ```bash
  ```


- 

  ```bash
  ```

- 

  ```bash
  ```

- 

  ```bash
  ```

- 

  ```bash
  ```

- 

  ```bash
  ```

- 

  ```bash
  ```

- 

  ```bash
  ```

- 

  ```bash
  ```

- 

  ```bash
  ```




