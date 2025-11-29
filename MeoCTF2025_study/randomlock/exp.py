from pwn import *
from ctypes import CDLL, c_int, c_uint

context(arch='amd64',os='linux',log_level='debug',endian='little')

p = process('./pwn')
p = remote('127.0.0.1',61234)
# libc = ELF('./libc.so.6')

# rand 产生的结果只会是1, rand没用, seed恒为1
libc = CDLL("libc.so.6")
libc.srandom(1)

for i in range(10):
    p.recvuntil(b'>')
    random_value = libc.random()%10000
    print(random_value)
    p.sendline(str(random_value).encode())

p.interactive()