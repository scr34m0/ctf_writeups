#!/usr/bin/python
# -*- coding: utf-8 -*-
# @arthurpaixao
from pwn import *
import string

cookie = 'a'
alphabet = string.ascii_lowercase + string.digits + '_-'


def getkey(a):
    p = remote('pwnable.kr', 9006)
    p.recvuntil('ID')
    p.sendline(a)
    p.recvuntil('PW')
    p.sendline('')
    r = p.recvuntil(')')
    p.close()
    return r[r.find('(') + 1:r.find(')')]


def guess(n):
    global cookie
    count = ((n + 2) / 16 + 1) * 32
    pre_padding = '-' * (15 - n + 16 * ((n + 2) / 16)) + cookie[:n]
    real = '-' * (13 - n + 16 * ((n + 2) / 16))
    key = getkey(real)[:count]
    print 'count:', count
    print 'pre_padding:', pre_padding
    print 'real:', real
    print 'key:', key
    for i in alphabet:
        print i
    for i in alphabet:
        print i
        if getkey(pre_padding + i)[:count] == key:
            print 'cookie got:', n, i
            cookie = cookie[:n] + i + cookie[n + 1:]
            return
    print 'Error.'
    print 'Guessed:', cookie[:n - 1]
    assert False


map(guess, range(0, 64))
print cookie

			
