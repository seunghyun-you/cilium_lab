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
