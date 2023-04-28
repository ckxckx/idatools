2023-04-26:

ida_syscall_record.py: 基于 ida debugger实现的程序system call执行记录器。

挑战：

1. 如何筛选指定进程的中断状态
2. 定位系统调用的入口、出口

设计：

1. 用户态切换到内核态，会执行swapgs指令，将断点设置在该swapgs执行之后，通过task_struct索引带有进程名信息的comm，比对comm和“指定进程”名，如若两者不匹配，ida将不做任何记录，并continue执行，否则进行定制化的操作
2. 定位system call的内核代码入口，设置断点，在内核执行中断时记录rax、rdi等寄存器的取值
3. 定位system call返回指令(sysret)前的指令地址，设置断点，在swapgs之前记录记录rax(系统调用返回值)

实现：

1. 通过解析内核函数"sys_getpid"的实现，获得current指针地址相对gs地址的偏移
2. 通过解析内核函数 "get_task_comm" 的实现，获得 comm 字符串数组相对current指向的task_struct结构的偏移

```
# current_gs_offset = get_current_offset()
# comm_current_offset = get_strncpy_param_offset("get_task_comm")
```

3. 入口位置：通过符号"entry_SYSCALL_64_after_swapgs"获得系统调用入口
4. 出口位置：通过符号"entry_SYSCALL_64"获得system call内核代码入口地址，在 get_sysret_list() 函数中通过反汇编0x100条指令搜索就近位置的sysret指令，将断点设置到sysret指令前的swapgs之前

测试：

  当前测试在linux-4.8上通过

  额外编译选项:

```
CONFIG_USER_NS=y  # 启用 unshare（NEW_USER） 功能
CONFIG_DEBUG_INFO=y # 启用支持pahole的功能
```



关键结果：

  系统调用序列存储在 syscall_list，系统调用返回值记录在syscall_ret_list中，

  使用过程的输入输出可以通过代码进行调整




探索：

- 考察如何直接通过条件断点简化目前的实现，或许还可以提高执行效率- 可以使用条件断点改进实现
  - 不好处理条件断点代码中的消息传递
  - 条件断点和定制化断点的优先级问题：条件断点优先于定制化断点
  - 放弃这个方案：conditional breakpoint虽然可以下断点，在system call这个方案里却并不合适，估计：每个condition脚本有相对独立的上下文空间，每个上下文都要import一遍依赖，由于syscall非常频繁，这种做法带来了过高的开销，还是保持原本方案比较好。

todo:

- syscall64_dict 字典没有收录序号100以上的syscall
- 考察如何直接通过条件断点简化目前的实现，或许还可以提高执行效率
  - 可以使用条件断点改进实现
  - 不好处理条件断点代码中的消息传递
  - 条件断点和定制化断点的优先级问题：条件断点优先于定制化断点
