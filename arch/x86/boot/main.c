/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *   Copyright 2009 Intel Corporation; author H. Peter Anvin
 *
 *   This file is part of the Linux kernel, and is made available under
 *   the terms of the GNU General Public License version 2.
 *
 * ----------------------------------------------------------------------- */

/*
 * Main module for the real-mode kernel code
 */

#include "boot.h"
#include "string.h"

struct boot_params boot_params __attribute__((aligned(16)));

char *HEAP = _end;
char *heap_end = _end;		/* Default end of heap = no heap */

/*
 * Copy the header into the boot parameter block.  Since this
 * screws up the old-style command line protocol, adjust by
 * filling in the new-style command line pointer instead.
 *
 * _start() [arch/x86/boot/header.S]
 *  start_of_setup() [arch/x86/boot/header.S]
 *   main()  [arxh/x86/boot/main.c]
 *    copy_boot_params() [arxh/x86/boot/main.c]
 */

static void copy_boot_params(void)
{
	struct old_cmdline {
		u16 cl_magic;
		u16 cl_offset;
	};
	const struct old_cmdline * const oldcmd =
		(const struct old_cmdline *)OLD_CL_ADDRESS;

	BUILD_BUG_ON(sizeof boot_params != 4096);
	memcpy(&boot_params.hdr, &hdr, sizeof hdr);

	if (!boot_params.hdr.cmd_line_ptr &&
	    oldcmd->cl_magic == OLD_CL_MAGIC) {
		/* Old-style command line protocol. */
		u16 cmdline_seg;

		/* Figure out if the command line falls in the region
		   of memory that an old kernel would have copied up
		   to 0x90000... */
		if (oldcmd->cl_offset < boot_params.hdr.setup_move_size)
			cmdline_seg = ds();
		else
			cmdline_seg = 0x9000;

		boot_params.hdr.cmd_line_ptr =
			(cmdline_seg << 4) + oldcmd->cl_offset;
	}
}

/*
 * Query the keyboard lock status as given by the BIOS, and
 * set the keyboard repeat rate to maximum.  Unclear why the latter
 * is done here; this might be possible to kill off as stale code.
 *
 * _start() [arch/x86/boot/header.S]
 *  start_of_setup() [arch/x86/boot/header.S]
 *   main()  [arxh/x86/boot/main.c]
 *    keyboard_init()
 */
static void keyboard_init(void)
{
	struct biosregs ireg, oreg;
	initregs(&ireg);

	ireg.ah = 0x02;		/* Get keyboard status */
	intcall(0x16, &ireg, &oreg);
	boot_params.kbd_status = oreg.al;

	ireg.ax = 0x0305;	/* Set keyboard repeat rate */
	intcall(0x16, &ireg, NULL);
}

/*
 * Get Intel SpeedStep (IST) information.
 */
static void query_ist(void)
{
	struct biosregs ireg, oreg;

	/* Some older BIOSes apparently crash on this call, so filter
	   it from machines too old to have SpeedStep at all. */
	if (cpu.level < 6)
		return;

	initregs(&ireg);
	ireg.ax  = 0xe980;	 /* IST Support */
	ireg.edx = 0x47534943;	 /* Request value */
	intcall(0x15, &ireg, &oreg);

	boot_params.ist_info.signature  = oreg.eax;
	boot_params.ist_info.command    = oreg.ebx;
	boot_params.ist_info.event      = oreg.ecx;
	boot_params.ist_info.perf_level = oreg.edx;
}

/*
 * Tell the BIOS what CPU mode we intend to run in.
 *
 * _start() [arch/x86/boot/header.S]
 *  start_of_setup() [arch/x86/boot/header.S]
 *   main()  [arxh/x86/boot/main.c]
 *    set_bios_mode()
 *
 * x86_64 特有，通过 BIOS 0x15 例程告知之后将进入 long mode 
 */
static void set_bios_mode(void)
{
#ifdef CONFIG_X86_64
	struct biosregs ireg;

	initregs(&ireg);
	ireg.ax = 0xec00;
	ireg.bx = 2;
	intcall(0x15, &ireg, NULL);
#endif
}

/*
 * _start() [arch/x86/boot/header.S]
 *  start_of_setup() [arch/x86/boot/header.S]
 *   main()  [arxh/x86/boot/main.c]
 *    init_heap()
 */
static void init_heap(void)
{
	char *stack_end;

	if (boot_params.hdr.loadflags & CAN_USE_HEAP) {
		 /* 计算当前栈底： stack_end = esp - STACK_SIZE */
		asm("leal %P1(%%esp),%0"
		    : "=r" (stack_end) : "i" (-STACK_SIZE));

        /* 计算堆底 */
		heap_end = (char *)
			((size_t)boot_params.hdr.heap_end_ptr + 0x200);

		 /* 确保堆紧挨着栈 */	
		if (heap_end > stack_end)
			heap_end = stack_end;
	} else {
		/* Boot protocol 2.00 only, no heap available */
		puts("WARNING: Ancient bootloader, some functionality "
		     "may be limited!\n");
	}
}

/*
 * _start() [arch/x86/boot/header.S]
 *  start_of_setup() [arch/x86/boot/header.S]
 *   main()  [arxh/x86/boot/main.c]
 */
void main(void)
{
	/* First, copy the boot header into the "zeropage" */
    /*
     * 从 header.S 中把 GRUB 设置的 setup_header 拷贝到 boot_params.hdr 中
     * 注意这里的 memcpy 不是 glibc 中的那个，而是定义在 copy.S 中的那个：
     * GLOBAL(memcpy)
     *   pushw %si
     *   pushw %di
     *   movw  %ax, %di
     *   movw  %dx, %si
     *   pushw %cx
     *   shrw  $2, %cx
     *   rep; movsl
     *   popw  %cx
     *   andw  $3, %cx
     *   rep; movsb
     *   popw  %di
     *   popw  %si
     *   retl
     * ENDPROC(memcpy)
     * 它通过 ax,dx,cx 来传参，先以 4byte 为单位进行拷贝，然后把剩下的以 byte 为单位进行拷贝
     * 如果 kernel 是使用老式的 command line protocol，更新 boot_params.hdr.cmd_line_ptr
     */
	copy_boot_params();

	/* Initialize the early-boot console */
    /*
     * 初始化 console，如果有 earlyprintk 选项，选择对应的设备作为 console，如 serial,0x3f8,115200
     * 此后可以通过 puts => putchar 输出字符，本质上是通过 0x10 中断调用 BIOS 例程来打印字符
     *
     * 在此之后，可以用puts输出字符串信息
     */	
	console_init();
	if (cmdline_find_option_bool("debug"))
		puts("early console in setup code\n");
	

	/* End of heap check */
	/* 如果开启了 CAN_USE_HEAP，初始化堆 */
	init_heap();

	/* Make sure we have all the proper CPU support */
	/* 检查当前特权级是否够运行 kernel，kernel 需要的 feature 是否都满足。通过 cpuid 或 rdmsr 获取 
	 *
	 * checking if the CPU supports long mode and SSE.
	 */
	if (validate_cpu()) {
		puts("Unable to boot - please use a kernel appropriate "
		     "for your CPU.\n");
		die();
	}

	/* Tell the BIOS what CPU mode we intend to run in. */
	/* x86_64 特有，通过 BIOS 0x15 例程告知之后将进入 long mode */
	set_bios_mode();

	/* Detect memory layout */
    /*
     * 检测内存布局是否符合要求
     * 共有 0xe820, 0xe801, 0x88 三种接口，最终都是发出 0x15 中断获取内存状态
     * 能够从 BIOS 得到可用、保留等内存区域的信息，得到每个内存区域的起始地址、长度和类型
     * 并将这些信息存到 boot_params.e820_map 中
     * 可通过 dmesg 查看，即跟在 BIOS-provided physical RAM map 后面那一坨
     */	
	detect_memory();

	/* Set keyboard repeat rate (why?) and query the lock flags */
	/* 键盘初始化，通过 BIOS 0x16 例程获取键盘状态，然后设置 repeat rate (按住不放产生字符的速率) */
	keyboard_init();

	/* Query Intel SpeedStep (IST) information 
	 *
	 * SpeedStep:
	 * https://en.wikipedia.org/wiki/SpeedStep
	 */
	query_ist();

	/* Query APM information 
	 *
	 * Advanced Power Management information 
	 */
	/* 通过 BIOS 0x15 例程获取 Advanced Power Management 信息，然后再次调用以连接 32 位接口(做两次，第二次是检查) */
#if defined(CONFIG_APM) || defined(CONFIG_APM_MODULE)
	query_apm_bios();
#endif

	/* Query EDD information */
    /* 获取所有 Enhanced Disk Drive(支持大容量磁盘设备)信息，存到 boot_params.eddbuf 和 boot_params.edd_mbr_sig_buffer 中 */
#if defined(CONFIG_EDD) || defined(CONFIG_EDD_MODULE)
	query_edd();
#endif

	/* Set the video mode */
	set_video();

	/* Do the last things and invoke protected mode */
	/* 切换到保护模式 */
	go_to_protected_mode();
}
