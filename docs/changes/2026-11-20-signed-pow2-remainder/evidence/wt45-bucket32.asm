
/tmp/dtvm-srem-study/signed_buckets.cwasm:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <wasm[0]::function[0]::bucket32>:
       0:	55                   	push   rbp
       1:	48 89 e5             	mov    rbp,rsp
       4:	85 d2                	test   edx,edx
       6:	0f 85 08 00 00 00    	jne    14 <wasm[0]::function[0]::bucket32+0x14>
       c:	48 33 c0             	xor    rax,rax
       f:	e9 3e 00 00 00       	jmp    52 <wasm[0]::function[0]::bucket32+0x52>
      14:	48 33 c0             	xor    rax,rax
      17:	81 c2 ff ff ff ff    	add    edx,0xffffffff
      1d:	69 f1 0d 66 19 00    	imul   esi,ecx,0x19660d
      23:	8d 8e 5f f3 6e 3c    	lea    ecx,[rsi+0x3c6ef35f]
      29:	48 89 cf             	mov    rdi,rcx
      2c:	c1 ff 09             	sar    edi,0x9
      2f:	c1 ef 16             	shr    edi,0x16
      32:	8d b4 3e 5f f3 6e 3c 	lea    esi,[rsi+rdi*1+0x3c6ef35f]
      39:	81 e6 00 fc ff ff    	and    esi,0xfffffc00
      3f:	48 89 cf             	mov    rdi,rcx
      42:	2b fe                	sub    edi,esi
      44:	48 63 f7             	movsxd rsi,edi
      47:	48 03 c6             	add    rax,rsi
      4a:	85 d2                	test   edx,edx
      4c:	0f 85 c5 ff ff ff    	jne    17 <wasm[0]::function[0]::bucket32+0x17>
      52:	48 89 ec             	mov    rsp,rbp
      55:	5d                   	pop    rbp
      56:	c3                   	ret
