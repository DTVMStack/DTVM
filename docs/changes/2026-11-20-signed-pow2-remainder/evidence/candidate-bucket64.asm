
/tmp/dtvm-srem-study/candidate-native/f1.bin:     file format binary


Disassembly of section .data:

0000000000000000 <.data>:
   0:	55                   	push   rbp
   1:	48 89 e5             	mov    rbp,rsp
   4:	48 83 ec 18          	sub    rsp,0x18
   8:	89 75 fc             	mov    DWORD PTR [rbp-0x4],esi
   b:	48 89 55 f0          	mov    QWORD PTR [rbp-0x10],rdx
   f:	48 8b 84 e4 00 c0 ff 	mov    rax,QWORD PTR [rsp+riz*8-0x4000]
  16:	ff
  17:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  1a:	85 c0                	test   eax,eax
  1c:	74 59                	je     0x77
  1e:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  21:	48 8b 4d f0          	mov    rcx,QWORD PTR [rbp-0x10]
  25:	48 ba 2d 7f 95 4c 2d 	movabs rdx,0x5851f42d4c957f2d
  2c:	f4 51 58
  2f:	48 0f af ca          	imul   rcx,rdx
  33:	48 ba 4f 81 67 f7 7e 	movabs rdx,0x14057b7ef767814f
  3a:	7b 05 14
  3d:	48 01 d1             	add    rcx,rdx
  40:	48 89 ca             	mov    rdx,rcx
  43:	48 c1 fa 3f          	sar    rdx,0x3f
  47:	48 be ff ff ff ff ff 	movabs rsi,0xffffffffff
  4e:	00 00 00
  51:	48 21 f2             	and    rdx,rsi
  54:	48 01 d1             	add    rcx,rdx
  57:	48 be ff ff ff ff ff 	movabs rsi,0xffffffffff
  5e:	00 00 00
  61:	48 21 f1             	and    rcx,rsi
  64:	48 29 d1             	sub    rcx,rdx
  67:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
  6b:	8d 40 ff             	lea    eax,[rax-0x1]
  6e:	89 c1                	mov    ecx,eax
  70:	89 4d fc             	mov    DWORD PTR [rbp-0x4],ecx
  73:	85 c0                	test   eax,eax
  75:	75 a7                	jne    0x1e
  77:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
  7b:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
  7f:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
  83:	48 83 c4 18          	add    rsp,0x18
  87:	5d                   	pop    rbp
  88:	c3                   	ret
