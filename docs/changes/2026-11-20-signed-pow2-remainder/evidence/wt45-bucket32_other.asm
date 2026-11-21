
/tmp/dtvm-srem-study/signed_buckets.cwasm:     file format elf64-x86-64


Disassembly of section .text:

00000000000000c0 <wasm[0]::function[2]::bucket32_other>:
      c0:	55                   	push   rbp
      c1:	48 89 e5             	mov    rbp,rsp
      c4:	85 d2                	test   edx,edx
      c6:	0f 85 08 00 00 00    	jne    d4 <wasm[0]::function[2]::bucket32_other+0x14>
      cc:	48 33 c0             	xor    rax,rax
      cf:	e9 5a 00 00 00       	jmp    12e <wasm[0]::function[2]::bucket32_other+0x6e>
      d4:	48 33 c0             	xor    rax,rax
      d7:	49 89 c0             	mov    r8,rax
      da:	48 89 d7             	mov    rdi,rdx
      dd:	81 c7 ff ff ff ff    	add    edi,0xffffffff
      e3:	69 f1 0d 66 19 00    	imul   esi,ecx,0x19660d
      e9:	8d 8e 5f f3 6e 3c    	lea    ecx,[rsi+0x3c6ef35f]
      ef:	48 89 c8             	mov    rax,rcx
      f2:	f7 2d 40 00 00 00    	imul   DWORD PTR [rip+0x40]        # 138 <wasm[0]::function[2]::bucket32_other+0x78>
      f8:	8d 84 32 5f f3 6e 3c 	lea    eax,[rdx+rsi*1+0x3c6ef35f]
      ff:	c1 f8 09             	sar    eax,0x9
     102:	48 89 c2             	mov    rdx,rax
     105:	c1 ea 1f             	shr    edx,0x1f
     108:	03 c2                	add    eax,edx
     10a:	69 c0 f1 03 00 00    	imul   eax,eax,0x3f1
     110:	48 89 ca             	mov    rdx,rcx
     113:	2b d0                	sub    edx,eax
     115:	48 63 d2             	movsxd rdx,edx
     118:	4c 89 c0             	mov    rax,r8
     11b:	48 03 c2             	add    rax,rdx
     11e:	85 ff                	test   edi,edi
     120:	0f 84 08 00 00 00    	je     12e <wasm[0]::function[2]::bucket32_other+0x6e>
     126:	49 89 c0             	mov    r8,rax
     129:	e9 af ff ff ff       	jmp    dd <wasm[0]::function[2]::bucket32_other+0x1d>
     12e:	48 89 ec             	mov    rsp,rbp
     131:	5d                   	pop    rbp
     132:	c3                   	ret
     133:	00 00                	add    BYTE PTR [rax],al
     135:	00 00                	add    BYTE PTR [rax],al
     137:	00 c3                	add    bl,al
     139:	22 e7                	and    ah,bh
     13b:	81                   	.byte 0x81
     13c:	00 00                	add    BYTE PTR [rax],al
	...
