
/tmp/dtvm-srem-study/candidate-native/f2.bin:     file format binary


Disassembly of section .data:

0000000000000000 <.data>:
   0:	55                   	push   rbp
   1:	48 89 e5             	mov    rbp,rsp
   4:	48 83 ec 38          	sub    rsp,0x38
   8:	89 75 fc             	mov    DWORD PTR [rbp-0x4],esi
   b:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
   e:	31 c0                	xor    eax,eax
  10:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
  14:	48 8b 84 e4 00 c0 ff 	mov    rax,QWORD PTR [rsp+riz*8-0x4000]
  1b:	ff
  1c:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  1f:	85 c0                	test   eax,eax
  21:	75 08                	jne    0x2b
  23:	31 c0                	xor    eax,eax
  25:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
  29:	eb 6d                	jmp    0x98
  2b:	31 c0                	xor    eax,eax
  2d:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
  31:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
  34:	48 8b 4d f0          	mov    rcx,QWORD PTR [rbp-0x10]
  38:	48 89 4d d8          	mov    QWORD PTR [rbp-0x28],rcx
  3c:	69 c0 0d 66 19 00    	imul   eax,eax,0x19660d
  42:	8d 80 5f f3 6e 3c    	lea    eax,[rax+0x3c6ef35f]
  48:	89 c1                	mov    ecx,eax
  4a:	89 4d ec             	mov    DWORD PTR [rbp-0x14],ecx
  4d:	89 45 e4             	mov    DWORD PTR [rbp-0x1c],eax
  50:	b9 f1 03 00 00       	mov    ecx,0x3f1
  55:	89 4d e8             	mov    DWORD PTR [rbp-0x18],ecx
  58:	3d 00 00 00 80       	cmp    eax,0x80000000
  5d:	75 0d                	jne    0x6c
  5f:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
  62:	31 d2                	xor    edx,edx
  64:	89 55 d4             	mov    DWORD PTR [rbp-0x2c],edx
  67:	83 f8 ff             	cmp    eax,0xffffffff
  6a:	74 0c                	je     0x78
  6c:	8b 4d e8             	mov    ecx,DWORD PTR [rbp-0x18]
  6f:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
  72:	99                   	cdq
  73:	f7 f9                	idiv   ecx
  75:	89 55 d4             	mov    DWORD PTR [rbp-0x2c],edx
  78:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  7b:	48 8b 4d d8          	mov    rcx,QWORD PTR [rbp-0x28]
  7f:	8b 55 d4             	mov    edx,DWORD PTR [rbp-0x2c]
  82:	48 63 d2             	movsxd rdx,edx
  85:	48 01 d1             	add    rcx,rdx
  88:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
  8c:	8d 40 ff             	lea    eax,[rax-0x1]
  8f:	89 c1                	mov    ecx,eax
  91:	89 4d fc             	mov    DWORD PTR [rbp-0x4],ecx
  94:	85 c0                	test   eax,eax
  96:	75 99                	jne    0x31
  98:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
  9c:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  a0:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  a4:	48 83 c4 38          	add    rsp,0x38
  a8:	5d                   	pop    rbp
  a9:	c3                   	ret
