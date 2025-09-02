# memhook

基于钩子函数的内存监视工具

请遵守 **GPL-3.0** 开源协议，开源您对本仓库的源码修改

更多讨论、反馈请联系邮箱 lion.yu@foxmail.com，欢迎使用反馈和改进意见！

## 核心原理

1. 钩子函数

    通过 LD_PRELOAD 预加载共享库符号，实现以自定义的 alloctor / deallocator 替换 libc 的默认实现，配合全局累加器记录内存占用的增减
    在自定义的 alloctor / deallocator 中通过 RTLD_NEXT 扩展调用 libc 的默认实现版本，还原其原本的功能

2. 多线程安全

    考虑到申请/释放的性能以及多线程安全的因素，在使用全局累加器时需要进行保护，建议采用 libc 提供的标准原子化功能

3. alloctor 的覆盖

    alloctor需要确保覆盖到所有的申请路径，不能重复、错漏
  + 显式申请释放
    - malloc
    - calloc
    - realloc
    - free
    - reallocarray (C11 / BSD)
    - posix_memalign
    - aligned_alloc
    - memalign
    - strdup
    - strndup
    过时的显式申请
    - valloc
    - pvalloc

  + 隐式申请释放
    - mmap / munmap
    - mmap64（32 位 glibc/uClibc 在 LFS 下会用到）
    - mremap
    - brk / sbrk (仅uclibc中需要hook)

  + 说明
    - 某些函数内部没有私有分配器，只是对 malloc 系列函数的薄封装，所以不需要 hook，这种函数有
      - strdup
      - strndup
      - reallocarray
    - 少数大型 C/C++ 库（如 OpenSSL、jemalloc、TCMalloc）可能会 直接 mmap + 内部簿记，不经过公共 malloc/free，如果程序静态链接了它们，则需要 hook 它们的私有分配器

4. deallocator 函数没有 size 的解决方法

    建立哈希表，在 alloctor 中将内存记录加入表中，释放时查表释放记录

5. 特别注意

    避免在 allocator 中直接/间接地调用 alloctor，否则会导致无限递归，从而引发段错误

    注意，即使是常见的 printf/snprintf/dprintf 这些格式化输出函数调用也隐含了 allocator 系列函数的调用

    例如首次 printf 调用会通过 malloc 申请 1K 字节的内存，这块内存在程序退出时释放

## 如何使用

参考 build.sh 脚本
1. 将 mem_hook.c 编译成动态库 libmemhook.so （运行 build.sh）
2. 复制 build.sh 生成的动态库和程序 libmemhook.so、monitor 到你的目标环境/平台
3. 修改环境变量 LD_PRELOAD 以追加 libmemhook.so 的路径或者像 build.sh 中一样在运行程序时再指定 LD_PRELOAD
4. 运行 monitor 程序，检验结果
