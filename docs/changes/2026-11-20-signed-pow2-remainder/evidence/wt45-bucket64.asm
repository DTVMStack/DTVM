
/tmp/dtvm-srem-study/signed_buckets.cwasm:     file format elf64-x86-64


Disassembly of section .text:

0000000000000060 <wasm[0]::function[1]::bucket64>:
      60:	55                   	push   rbp
      61:	48 89 e5             	mov    rbp,rsp
      64:	85 d2                	test   edx,edx
      66:	0f 84 3b 00 00 00    	je     a7 <wasm[0]::function[1]::bucket64+0x47>
      6c:	81 c2 ff ff ff ff    	add    edx,0xffffffff
      72:	48 0f af 0d 36 00 00 	imul   rcx,QWORD PTR [rip+0x36]        # b0 <wasm[0]::function[1]::bucket64+0x50>
      79:	00
      7a:	48 b8 4f 81 67 f7 7e 	movabs rax,0x14057b7ef767814f
      81:	7b 05 14
      84:	48 03 c8             	add    rcx,rax
      87:	48 89 c8             	mov    rax,rcx
      8a:	48 c1 f8 27          	sar    rax,0x27
      8e:	48 c1 e8 18          	shr    rax,0x18
      92:	48 03 c1             	add    rax,rcx
      95:	48 23 05 1c 00 00 00 	and    rax,QWORD PTR [rip+0x1c]        # b8 <wasm[0]::function[1]::bucket64+0x58>
      9c:	48 2b c8             	sub    rcx,rax
      9f:	85 d2                	test   edx,edx
      a1:	0f 85 c5 ff ff ff    	jne    6c <wasm[0]::function[1]::bucket64+0xc>
      a7:	48 89 c8             	mov    rax,rcx
      aa:	48 89 ec             	mov    rsp,rbp
      ad:	5d                   	pop    rbp
      ae:	c3                   	ret
      af:	00 2d 7f 95 4c 2d    	add    BYTE PTR [rip+0x2d4c957f],ch        # 2d4c9634 <signatures[1]::wasm_to_array_trampoline+0x2d4c92a1>
      b5:	f4                   	hlt
      b6:	51                   	push   rcx
      b7:	58                   	pop    rax
      b8:	00 00                	add    BYTE PTR [rax],al
      ba:	00 00                	add    BYTE PTR [rax],al
      bc:	00 ff                	add    bh,bh
      be:	ff                   	(bad)
      bf:	ff                   	.byte 0xff
