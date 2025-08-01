### VxLAN (표준)

- 데이터 센터는 서버 가상화 기능이 도입되면서 네트워크 인프라에 대한 요구사항이 증가했다.

- 데이터 센터에서 VLAN은 경우에 따라서 수천 개가 필요할 수 있는데, 그 자체 제한인 4,094는 적합하지 않다.

- 멀티 테넌트 구조를 가져가야 하는 상황에서 자체 격리된 네트워크를 구성하게 되는데, 이 때 독립적인 MAC 주소나 VLAN ID가 중복될 우려가 있다.

- 이러한 요구사항들로 인해 오버레이 네트워크의 필요성이 만들어진다.

- 오버레이 네트워크에서는 VM의 MAC 주소 교환 시 트래픽을 논리적인 '터널'을 통해 캡슐화된 형식으로 전송한다.

- VxLAN에서는 터널을 구성할 때 L3 네트워크 위에서 L2 네트워크를 구현하는 기술이다.

- L2 이더넷 프레임을 UDP 패킷 안에 캡슐화해서 기존 L3 네트워크(IP 네트워크)를 통해 전송한다.

- 이 기술을 이용하면 물리적으로는 분리된 네트워크지만 마치 같은 L2 네트워크에 연결된 것처럼 통신할 수 있다.

- 이 때 양 쪽 네트워크의 끝단에서는 VTEP(VXLAN Tunnel Endpoint)이 통해 캡슐화/역캡슐화, 터널 관리 작업을 수행한다.

- 이 때 트래픽의 구성에는 원본 이더넷 헤더/VXLAN 헤더/UDP 헤더/ 외부 IP &\* 이더넷 헤더가 들어간다.

  - 원본 프레임(L7~L2 > L7) : VM이 보내려는 프레임들 전체를 VxLAN 프레임의 페이로드로 들어간다.

  - VXLAN 헤더(L5) : VNI 정보가 들어가 있고, 같은 VNI를 가지는 VM들 간에는 통신이 가능해진다.

  - UDP 헤더(L4) : Port 번호가 들어간다

  - 외부 IP(L3) & 헤더(L2) : 송/수신 측 IP and Header 값이 들어간다.

### Geneve

- VxLAN 와 동일한 매커니즘으로 동작하는 네트워크 가상화 기술이다.

- VxLAN, NVGRE 같은 기존 이니셔티브들을 통합하려는 목적으로 IETF에서 만든 캡슐화 프로토콜이다.

- 주요 차이점

  - 헤더 크기 : VxLAN 8 Bytes → Geneve 16 Bytes

  - 기능 : 전송 보안, 서비스 체이닝, 인밴드 텔레메트리

  - 유연성 : 프로토콜 타입 필드를 포함해 모든 종류의 네트워크 트래픽 캡슐화 가능

### Encapsulation Mode 의 클러스터 네트워크

- 클러스터 내부 네트워크는 기본 네트워크(노드 네트워크)에 대한 의존성이 없다.

  - 노드를 연결하는 네트워크는 Pod CIDR을 인식할 필요가 없다.

  - 노드간의 통신이 보장된다면 Pod 통신도 보장된다.

- 기본 네트워크에 대한 의존성이 없으므로 Pod가 사용할 수 있는 IP 주소 세트가 훨씬 더 많아질 수 있다.

- 클러스터에 참여하는 새 노드는 자동으로 오버레이에 통합된다,
