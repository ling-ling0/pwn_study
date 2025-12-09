11.26:  system 函数需要栈对齐

11.27:  shellcode 注意架构 段权限问题
        pop rdi 的用法 system 的参数要求 x86架构传参

11.28   为随机数爆破 栈结构检查 Canary 爆破(假)
        不同类型数据的大小 依旧 system 栈对齐
        虚假的 pwn 真正的指令过滤绕过 

11.29   依旧伪随机

12.9    C 格式字符串函数格式 
        (read 从 stdin 输入多的会填入下一次输入)
        syscall 的调用格式