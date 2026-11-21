
/tmp/dtvm-srem-study/main-native/f1.bin:     file format binary


Disassembly of section .data:

0000000000000000 <.data>:
   0:	55                   	push   rbp
   1:	48 89 e5             	mov    rbp,rsp
   4:	48 83 ec 30          	sub    rsp,0x30
   8:	89 75 fc             	mov    DWORD PTR [rbp-0x4],esi
   b:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   f:	48 8b 84 e4 00 c0 ff 	mov    rax,QWORD PTR [rsp+riz*8-0x4000]
  16:	ff
  17:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  1a:	85 c0                	test   eax,eax
  1c:	74 7a                	je     0x98
  1e:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
  22:	48 b9 2d 7f 95 4c 2d 	movabs rcx,0x5851f42d4c957f2d
  29:	f4 51 58
  2c:	48 0f af c1          	imul   rax,rcx
  30:	48 b9 4f 81 67 f7 7e 	movabs rcx,0x14057b7ef767814f
  37:	7b 05 14
  3a:	48 01 c8             	add    rax,rcx
  3d:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  41:	48 b9 00 00 00 00 00 	movabs rcx,0x10000000000
  48:	01 00 00
  4b:	48 89 4d e8          	mov    QWORD PTR [rbp-0x18],rcx
  4f:	48 b9 00 00 00 00 00 	movabs rcx,0x8000000000000000
  56:	00 00 80
  59:	48 39 c8             	cmp    rax,rcx
  5c:	75 12                	jne    0x70
  5e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
  62:	31 c9                	xor    ecx,ecx
  64:	89 ca                	mov    edx,ecx
  66:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
  6a:	48 83 f8 ff          	cmp    rax,0xffffffffffffffff
  6e:	74 11                	je     0x81
  70:	48 8b 4d e8          	mov    rcx,QWORD PTR [rbp-0x18]
  74:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
  78:	48 99                	cqo
  7a:	48 f7 f9             	idiv   rcx
  7d:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
  81:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  84:	48 8b 4d d8          	mov    rcx,QWORD PTR [rbp-0x28]
  88:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
  8c:	8d 40 ff             	lea    eax,[rax-0x1]
  8f:	89 c1                	mov    ecx,eax
  91:	89 4d fc             	mov    DWORD PTR [rbp-0x4],ecx
  94:	85 c0                	test   eax,eax
  96:	75 86                	jne    0x1e
  98:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
  9c:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  a0:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  a4:	48 83 c4 30          	add    rsp,0x30
  a8:	5d                   	pop    rbp
  a9:	c3                   	ret
