
/tmp/dtvm-srem-study/candidate-native/f0.bin:     file format binary


Disassembly of section .data:

0000000000000000 <.data>:
   0:	55                   	push   rbp
   1:	48 89 e5             	mov    rbp,rsp
   4:	48 83 ec 20          	sub    rsp,0x20
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
  29:	eb 4c                	jmp    0x77
  2b:	31 c0                	xor    eax,eax
  2d:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
  31:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  34:	48 8b 4d f0          	mov    rcx,QWORD PTR [rbp-0x10]
  38:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
  3b:	69 d2 0d 66 19 00    	imul   edx,edx,0x19660d
  41:	8d 92 5f f3 6e 3c    	lea    edx,[rdx+0x3c6ef35f]
  47:	89 d6                	mov    esi,edx
  49:	89 75 ec             	mov    DWORD PTR [rbp-0x14],esi
  4c:	89 d6                	mov    esi,edx
  4e:	c1 fe 1f             	sar    esi,0x1f
  51:	81 e6 ff 03 00 00    	and    esi,0x3ff
  57:	01 f2                	add    edx,esi
  59:	81 e2 ff 03 00 00    	and    edx,0x3ff
  5f:	29 f2                	sub    edx,esi
  61:	48 63 d2             	movsxd rdx,edx
  64:	48 01 d1             	add    rcx,rdx
  67:	48 89 4d f0          	mov    QWORD PTR [rbp-0x10],rcx
  6b:	8d 40 ff             	lea    eax,[rax-0x1]
  6e:	89 c1                	mov    ecx,eax
  70:	89 4d fc             	mov    DWORD PTR [rbp-0x4],ecx
  73:	85 c0                	test   eax,eax
  75:	75 ba                	jne    0x31
  77:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
  7b:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
  7f:	48 8b 45 e0          	mov    rax,QWORD PTR [rbp-0x20]
  83:	48 83 c4 20          	add    rsp,0x20
  87:	5d                   	pop    rbp
  88:	c3                   	ret
