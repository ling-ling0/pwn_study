from pwn import *

context(arch='amd64',log_level='debug',os='linux',endian='little')

p = process('./pwn')

