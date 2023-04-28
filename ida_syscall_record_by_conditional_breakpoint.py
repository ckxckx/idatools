from idaapi import *
import idaapi
import ida_dbg
import angrdbg
import idangr
import angr
from datetime import datetime
import idc

import re
import idc
import ida_dbg
import struct

# def generate_expresssions():

import pickle
import base64


import traceback



import re
import idaapi



import idaapi


def set_python_bpt(ea, cond):
    ''' Set conditional breakpoint with Python function 

        Usage:
        set_python_bpt(0x08000688, 'view_regs()')    
    '''
    idaapi.add_bpt(ea)
    bpt = idaapi.bpt_t()
    idaapi.get_bpt(ea, bpt)
    bpt.elang = 'Python'
    bpt.condition = cond
    idaapi.update_bpt(bpt)

ea = 0x4004F2
# cond = 'judge()'

# cond = '''
# def judge():
#     addr = 0x601030
#     aaaa = idc.read_dbg_memory(addr,4)
#     value=struct.unpack("<I",aaaa)[0]
#     if value == 0:
#         return False     
#     else:
#         return True
# return judge()
# '''
# set_python_bpt(ea, cond)

def get_strncpy_param_offset(func_name):
    # 获取函数地址
    func_addr = idaapi.get_name_ea(0, func_name)

    # 获取函数对象
    func = idaapi.get_func(func_addr)

    # 反汇编函数
    dism = idaapi.decompile(func)

    # 从反汇编结果中查找strncpy函数的调用语句
    pattern = r"strncpy(.+?)\);"
    match = re.search(pattern, str(dism))

    if match:
        # 获取strncpy函数的第二个参数的值
        param2 = re.search(r"a2 \+ (\d+)", match.group(1)).group(1)
        return int(param2)
    else:
        return None







def get_current_offset():
    import idaapi

    # 获取函数地址
    func_ea = idaapi.get_name_ea(0, "sys_getpid")

    # 获取函数对象
    func_til = idaapi.get_func(func_ea).start_ea

    # 反汇编函数
    disasm = idaapi.decompile(func_til)

    # 打印反汇编结果
    # print(disasm)

    if "readgsqword" in str(disasm):
        # 使用正则表达式提取readgsqword后括号中的内容
        text = str(disasm)
        match = re.search(r'0x[\da-fA-F]+', text)
        if match:
            hex_num = match.group()
            # print(hex_num)
            return int(hex_num,16)
        else:
            print("No match found")



# comm_current_offset = get_strncpy_param_offset("get_task_comm")
# current_gs_offset = get_current_offset()







# ida_dbg.get_reg_val


def get_current_pointer():
    # current_pointer = idc.GetRegValue("gs:" + hex(current_gs_offset))
    gs_base = ida_dbg.get_reg_val("gs_base")
    current_gs_offset = get_current_offset()
    current_address = gs_base + current_gs_offset
    # current_pointer = idc.GetQword(current_address)
    current_pointer_bts = idc.read_dbg_memory(current_address,8)
    current_pointer=struct.unpack("<Q",current_pointer_bts)[0]
    return current_pointer


def get_comm_name():
    current_pointer = get_current_pointer()
    comm_current_offset = get_strncpy_param_offset("get_task_comm")
    comm_address = current_pointer + comm_current_offset
    # comm_name = idc.GetString(comm_address)
    comm_name_16bts = idc.read_dbg_memory(comm_address,16)
    # print(comm_name_16bts)

    comm_name = comm_name_16bts.split(b'\x00', 1)[0].decode('utf-8', 'ignore')
    # print(comm_name)
    return comm_name



def func3():
    traceback.print_stack()

def restart_process():
    ida_dbg.request_exit_process()
    ida_dbg.request_start_process()
    ida_dbg.run_requests()
def continue_process():
    ida_dbg.request_continue_process()
    ida_dbg.run_requests()




syscall64_dict = {
    0: ('read', 'unsigned int fd', 'char *buf', 'size_t count'),
    1: ('write', 'unsigned int fd', 'const char *buf', 'size_t count'),
    2: ('open', 'const char *filename', 'int flags', 'mode_t mode'),
    3: ('close', 'unsigned int fd'),
    4: ('stat', 'const char *filename', 'struct stat *statbuf'),
    5: ('fstat', 'unsigned int fd', 'struct stat *statbuf'),
    6: ('lstat', 'const char *filename', 'struct stat *statbuf'),
    7: ('poll', 'struct pollfd *ufds', 'nfds_t nfds', 'int timeout'),
    8: ('lseek', 'unsigned int fd', 'off_t offset', 'unsigned int whence'),
    9: ('mmap', 'void *addr', 'size_t length', 'int prot', 'int flags', 'int fd', 'off_t offset'),
    10: ('mprotect', 'void *addr', 'size_t len', 'int prot'),
    11: ('munmap', 'void *addr', 'size_t length'),
    12: ('brk', 'void *brk'),
    13: ('rt_sigaction', 'int signum', 'const struct sigaction *act', 'struct sigaction *oldact'),
    14: ('rt_sigprocmask', 'int how', 'sigset_t *set', 'sigset_t *oldset'),
    15: ('rt_sigreturn',),
    16: ('ioctl', 'unsigned int fd', 'unsigned int cmd', 'unsigned long arg'),
    17: ('pread64', 'unsigned int fd', 'char *buf', 'size_t count', 'loff_t pos'),
    18: ('pwrite64', 'unsigned int fd', 'const char *buf', 'size_t count', 'loff_t pos'),
    19: ('readv', 'unsigned long fd', 'const struct iovec *vec', 'unsigned long vlen'),
    20: ('writev', 'unsigned long fd', 'const struct iovec *vec', 'unsigned long vlen'),
    21: ('access', 'const char *filename', 'int mode'),
    22: ('pipe', 'int *fildes'),
    23: ('select', 'int n', 'fd_set *inp', 'fd_set *outp', 'fd_set *exp', 'struct timeval *tvp'),
    24: ('sched_yield',),
    25: ('mremap', 'void *addr', 'size_t old_len', 'size_t new_len', 'unsigned long flags', 'void *new_addr'),
    26: ('msync', 'void *addr', 'size_t length', 'int flags'),
    27: ('mincore', 'unsigned long start', 'size_t len', 'unsigned char *vec'),
    28: ('madvise', 'void *start', 'size_t len', 'int behavior'),
    29: ('shmget', 'key_t key', 'size_t size', 'int flags'),
    30: ('shmat', 'int shmid', 'char *shmaddr', 'int shmflg'),
    31: ('shmctl', 'int shmid', 'int cmd', 'struct shmid_ds *buf'),
    32: ('dup', 'unsigned int fildes'),
    33: ('dup2', 'unsigned int oldfd', 'unsigned int newfd'),
    34: ('pause',),
    35: ('nanosleep', 'struct timespec *rqtp', 'struct timespec *rmtp'),
    36: ('getitimer', 'int which', 'struct itimerval *value'),
    37: ('alarm', 'unsigned int seconds'),
    38: ('setitimer', 'int which', 'struct itimerval *value', 'struct itimerval *ovalue'),
    39: ('getpid',),
    40: ('sendfile', 'int out_fd', 'int in_fd', 'off_t *offset', 'size_t count'),
    41: ('socket', 'int family', 'int type', 'int protocol'),
    42: ('connect', 'int sockfd', 'const struct sockaddr *addr', 'socklen_t addrlen'),
    43: ('accept', 'int sockfd', 'struct sockaddr *addr', 'socklen_t *addrlen'),
    44: ('sendto', 'int sockfd', 'const void *buf', 'size_t len', 'unsigned int flags', 'const struct sockaddr *dest_addr', 'socklen_t addrlen'),
    45: ('recvfrom', 'int sockfd', 'void *buf', 'size_t len', 'unsigned int flags', 'struct sockaddr *src_addr', 'socklen_t *addrlen'),
    46: ('sendmsg', 'int sockfd', 'const struct msghdr *msg', 'unsigned int flags'),
    47: ('recvmsg', 'int sockfd', 'struct msghdr *msg', 'unsigned int flags'),
    48: ('shutdown', 'int sockfd', 'int how'),
    49: ('bind', 'int sockfd', 'const struct sockaddr *addr', 'socklen_t addrlen'),
    50: ('listen', 'int sockfd', 'int backlog'),
    51: ('getsockname', 'int sockfd', 'struct sockaddr *addr', 'socklen_t *addrlen'),
    52: ('getpeername', 'int sockfd', 'struct sockaddr *addr', 'socklen_t *addrlen'),
    53: ('socketpair', 'int family', 'int type', 'int protocol', 'int *sv')
}



def get_sysret_list():
    def disassemble_n_instructions(start_address, n):
        instructions = []
        current_address = start_address

        for _ in range(n):
            # 获取指令的长度
            instruction_size = idc.get_item_size(current_address)

            # 获取指令的反汇编表示
            disasm = idc.generate_disasm_line(current_address, 0)

            # 将反汇编指令添加到列表中
            instructions.append((current_address, disasm))

            # 更新地址以获取下一条指令
            current_address += instruction_size

        return instructions

    # 指定要开始反汇编的地址（请根据实际情况修改）


    symbol_name ="entry_SYSCALL_64"
    ea = idc.get_name_ea_simple(symbol_name)
    start_address = ea
    instructions_count = 0x100

    # 执行反汇编并打印结果

    sysret_list = []
    instructions = disassemble_n_instructions(start_address, instructions_count)
    for addr, disasm in instructions:
        if disasm =="sysret":
            print("0x{:08X}: {}".format(addr, disasm))
            sysret_list.append(addr)
    return sysret_list

def record_syscall():
    # ida_dbg.get_reg_val("gs_base")
    item = []
    rax = ida_dbg.get_reg_val("rax")
    rdi = ida_dbg.get_reg_val("rdi")
    rsi = ida_dbg.get_reg_val("rsi")
    rdx = ida_dbg.get_reg_val("rdx")
    rcx = ida_dbg.get_reg_val("rcx")
    r8 = ida_dbg.get_reg_val("r8")
    r9 = ida_dbg.get_reg_val("r9")
    if syscall64_dict.__contains__(rax):
        syscall_name = syscall64_dict[rax][0]
    else:
        syscall_name = "unknown_syscall"
    item.append(syscall_name)
    return item



def record_syscall_ret():
    item = ida_dbg.get_reg_val("rax")
    return item


def set_python_bpt(ea, cond):
    ''' Set conditional breakpoint with Python function 

        Usage:
        set_python_bpt(0x08000688, 'view_regs()')    
    '''
    idaapi.add_bpt(ea)
    bpt = idaapi.bpt_t()
    idaapi.get_bpt(ea, bpt)
    bpt.elang = 'Python'
    bpt.condition = cond
    idaapi.update_bpt(bpt)




# 这里有个bug
syscall_list = []
syscall_ret_list = []
sysret_list = []
break_sysret_list =[]

class MyDbgHook(DBG_Hooks):
    def dbg_bpt(self, tid, ea):
        global syscall_list
        global syscall_ret_list
        global sysret_list
        global break_sysret_list
        commname=get_comm_name()


        if ea  == ea_entry:
            print("=====================================")
            item = record_syscall()
            syscall_list.append(item)
            print("syscall: " + item[0])
            continue_process()
            pass
        elif ea in break_sysret_list:
            item = record_syscall_ret()
            syscall_ret_list.append(item)
            continue_process()
        # if commname == "curl":
        #     if ea  == ea_entry:
        #         print("=====================================")
        #         item = record_syscall()
        #         syscall_list.append(item)
        #         print("syscall: " + item[0])
        #         continue_process()
        #         pass
        #     elif ea in break_sysret_list:
        #         item = record_syscall_ret()
        #         syscall_ret_list.append(item)
        #         continue_process()
        # else:
        #     print(">>>>>> not expected <<<<<<<")
        #     continue_process()
        return 0


       
try:
    if debughook:
        print("Removing previous hook ...")
        debughook.unhook()
except:
    pass



now1 = datetime.now() 

debughook = MyDbgHook()
debughook.hook()



func_name = "entry_SYSCALL_64_after_swapgs"
func_addr = idaapi.get_name_ea(0, func_name)
# ida_dbg.add_bpt(func_addr)




# 实际速率更慢了，条件断点的每个位置都需要import一遍上下文 ... 
# 所以这种模式宣告失败。

cond_specify_comm_fmt=r'''
import re
import idaapi
import idc
import ida_dbg
import struct

# comm_current_offset = get_strncpy_param_offset("get_task_comm")
# current_gs_offset = get_current_offset()

def get_strncpy_param_offset(func_name):
    # 获取函数地址
    func_addr = idaapi.get_name_ea(0, func_name)

    # 获取函数对象
    func = idaapi.get_func(func_addr)

    # 反汇编函数
    dism = idaapi.decompile(func)

    # 从反汇编结果中查找strncpy函数的调用语句
    pattern = r"strncpy(.+?)\);"
    match = re.search(pattern, str(dism))

    if match:
        # 获取strncpy函数的第二个参数的值
        param2 = re.search(r"a2 \+ (\d+)", match.group(1)).group(1)
        return int(param2)
    else:
        return None
def get_current_offset():
    # 获取函数地址
    func_ea = idaapi.get_name_ea(0, "sys_getpid")

    # 获取函数对象
    func_til = idaapi.get_func(func_ea).start_ea

    # 反汇编函数
    disasm = idaapi.decompile(func_til)

    # 打印反汇编结果
    # print(disasm)

    if "readgsqword" in str(disasm):
        # 使用正则表达式提取readgsqword后括号中的内容
        text = str(disasm)
        match = re.search(r'0x[\da-fA-F]+', text)
        if match:
            hex_num = match.group()
            # print(hex_num)
            return int(hex_num,16)
        else:
            print("No match found")

def get_current_pointer():
    # current_pointer = idc.GetRegValue("gs:" + hex(current_gs_offset))
    gs_base = ida_dbg.get_reg_val("gs_base")
    current_gs_offset = get_current_offset()
    current_address = gs_base + current_gs_offset
    # current_pointer = idc.GetQword(current_address)
    current_pointer_bts = idc.read_dbg_memory(current_address,8)
    current_pointer=struct.unpack("<Q",current_pointer_bts)[0]
    return current_pointer

def get_comm_name():
    current_pointer = get_current_pointer()
    comm_current_offset = get_strncpy_param_offset("get_task_comm")
    comm_address = current_pointer + comm_current_offset
    # comm_name = idc.GetString(comm_address)
    comm_name_16bts = idc.read_dbg_memory(comm_address,16)
    # print(comm_name_16bts)

    comm_name = comm_name_16bts.split(b'\x00', 1)[0].decode('utf-8', 'ignore')
    # print(comm_name)
    return comm_name

def judge_comm(comm_name_ref):
    comm_name = get_comm_name()
    if comm_name == comm_name_ref:
        return True
    else:
        return False

return judge_comm("{comm_name_ref}")
'''


cond_specify_comm = cond_specify_comm_fmt.format(comm_name_ref="curl")

set_python_bpt(func_addr, cond_specify_comm)

ea_entry = func_addr

sysret_list = get_sysret_list()


for ea in sysret_list:
    # ida_dbg.add_bpt(ea-3) # break before swapgs
    set_python_bpt(ea-3, cond_specify_comm)
    break_sysret_list.append(ea-3)





    
# run /Users/ckx/Desktop/aivee_codes/dev/ida_get_comm.py