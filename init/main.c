/*
 *  linux/init/main.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  GK 2/5/95  -  Changed to support mounting root fs via NFS
 *  Added initrd & change_root: Werner Almesberger & Hans Lermen, Feb '96
 *  Moan early if gcc is old, avoiding bogus kernels - Paul Gortmaker, May '96
 *  Simplified starting of init:  Michael A. Griffith <grif@acm.org>
 */

#define DEBUG		/* Enable initcall_debug */

#include <linux/types.h>
#include <linux/extable.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/binfmts.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/stackprotector.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/bootmem.h>
#include <linux/acpi.h>
#include <linux/console.h>
#include <linux/nmi.h>
#include <linux/percpu.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/kernel_stat.h>
#include <linux/start_kernel.h>
#include <linux/security.h>
#include <linux/smp.h>
#include <linux/profile.h>
#include <linux/rcupdate.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/writeback.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/cgroup.h>
#include <linux/efi.h>
#include <linux/tick.h>
#include <linux/sched/isolation.h>
#include <linux/interrupt.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <linux/rmap.h>
#include <linux/mempolicy.h>
#include <linux/key.h>
#include <linux/buffer_head.h>
#include <linux/page_ext.h>
#include <linux/debug_locks.h>
#include <linux/debugobjects.h>
#include <linux/lockdep.h>
#include <linux/kmemleak.h>
#include <linux/pid_namespace.h>
#include <linux/device.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/sched/init.h>
#include <linux/signal.h>
#include <linux/idr.h>
#include <linux/kgdb.h>
#include <linux/ftrace.h>
#include <linux/async.h>
#include <linux/sfi.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/pti.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/sched/clock.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/context_tracking.h>
#include <linux/random.h>
#include <linux/list.h>
#include <linux/integrity.h>
#include <linux/proc_ns.h>
#include <linux/io.h>
#include <linux/cache.h>
#include <linux/rodata_test.h>
#include <linux/jump_label.h>
#include <linux/mem_encrypt.h>

#include <asm/io.h>
#include <asm/bugs.h>
#include <asm/setup.h>
#include <asm/sections.h>
#include <asm/cacheflush.h>

#define CREATE_TRACE_POINTS
#include <trace/events/initcall.h>

static int kernel_init(void *);

extern void init_IRQ(void);
extern void fork_init(void);
extern void radix_tree_init(void);

/*
 * Debug helper: via this flag we know that we are in 'early bootup code'
 * where only the boot processor is running with IRQ disabled.  This means
 * two things - IRQ must not be enabled before the flag is cleared and some
 * operations which are not allowed with IRQ disabled are allowed while the
 * flag is set.
 */
bool early_boot_irqs_disabled __read_mostly;

enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

extern void time_init(void);
/* Default late time init is NULL. archs can override this later. */
void (*__initdata late_time_init)(void);

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];
/* Untouched saved command line (eg. for /proc) */
char *saved_command_line;
/* Command line for parameter parsing */
static char *static_command_line;
/* Command line for per-initcall parameter parsing */
static char *initcall_command_line;

static char *execute_command;
static char *ramdisk_execute_command;

/*
 * Used to generate warnings if static_key manipulation functions are used
 * before jump_label_init is called.
 */
bool static_key_initialized __read_mostly;
EXPORT_SYMBOL_GPL(static_key_initialized);

/*
 * If set, this is an indication to the drivers that reset the underlying
 * device before going ahead with the initialization otherwise driver might
 * rely on the BIOS and skip the reset operation.
 *
 * This is useful if kernel is booting in an unreliable environment.
 * For ex. kdump situation where previous kernel has crashed, BIOS has been
 * skipped and devices will be in unknown state.
 */
unsigned int reset_devices;
EXPORT_SYMBOL(reset_devices);

static int __init set_reset_devices(char *str)
{
	reset_devices = 1;
	return 1;
}

__setup("reset_devices", set_reset_devices);

static const char *argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
const char *envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

extern const struct obs_kernel_param __setup_start[], __setup_end[];

static bool __init obsolete_checksetup(char *line)
{
	const struct obs_kernel_param *p;
	bool had_early_param = false;

	p = __setup_start;
	do {
		int n = strlen(p->str);
		if (parameqn(line, p->str, n)) {
			if (p->early) {
				/* Already done in parse_early_param?
				 * (Needs exact match on param part).
				 * Keep iterating, as we can have early
				 * params and __setups of same names 8( */
				if (line[n] == '\0' || line[n] == '=')
					had_early_param = true;
			} else if (!p->setup_func) {
				pr_warn("Parameter %s is obsolete, ignored\n",
					p->str);
				return true;
			} else if (p->setup_func(line + n))
				return true;
		}
		p++;
	} while (p < __setup_end);

	return had_early_param;
}

/*
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
unsigned long loops_per_jiffy = (1<<12);
EXPORT_SYMBOL(loops_per_jiffy);

static int __init debug_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_DEBUG;
	return 0;
}

static int __init quiet_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_QUIET;
	return 0;
}

early_param("debug", debug_kernel);
early_param("quiet", quiet_kernel);

static int __init loglevel(char *str)
{
	int newlevel;

	/*
	 * Only update loglevel value when a correct setting was passed,
	 * to prevent blind crashes (when loglevel being set to 0) that
	 * are quite hard to debug
	 */
	if (get_option(&str, &newlevel)) {
		console_loglevel = newlevel;
		return 0;
	}

	return -EINVAL;
}

early_param("loglevel", loglevel);

/* Change NUL term back to "=", to make "param" the whole string. */
static int __init repair_env_string(char *param, char *val,
				    const char *unused, void *arg)
{
	if (val) {
		/* param=val or param="val"? */
		if (val == param+strlen(param)+1)
			val[-1] = '=';
		else if (val == param+strlen(param)+2) {
			val[-2] = '=';
			memmove(val-1, val, strlen(val)+1);
			val--;
		} else
			BUG();
	}
	return 0;
}

/* Anything after -- gets handed straight to init. */
static int __init set_init_arg(char *param, char *val,
			       const char *unused, void *arg)
{
	unsigned int i;

	if (panic_later)
		return 0;

	repair_env_string(param, val, unused, NULL);

	for (i = 0; argv_init[i]; i++) {
		if (i == MAX_INIT_ARGS) {
			panic_later = "init";
			panic_param = param;
			return 0;
		}
	}
	argv_init[i] = param;
	return 0;
}

/*
 * Unknown boot options get handed to init, unless they look like
 * unused parameters (modprobe will find them in /proc/cmdline).
 */
static int __init unknown_bootoption(char *param, char *val,
				     const char *unused, void *arg)
{
	repair_env_string(param, val, unused, NULL);

	/* Handle obsolete-style parameters */
	if (obsolete_checksetup(param))
		return 0;

	/* Unused module parameter. */
	if (strchr(param, '.') && (!val || strchr(param, '.') < val))
		return 0;

	if (panic_later)
		return 0;

	if (val) {
		/* Environment option */
		unsigned int i;
		for (i = 0; envp_init[i]; i++) {
			if (i == MAX_INIT_ENVS) {
				panic_later = "env";
				panic_param = param;
			}
			if (!strncmp(param, envp_init[i], val - param))
				break;
		}
		envp_init[i] = param;
	} else {
		/* Command line option */
		unsigned int i;
		for (i = 0; argv_init[i]; i++) {
			if (i == MAX_INIT_ARGS) {
				panic_later = "init";
				panic_param = param;
			}
		}
		argv_init[i] = param;
	}
	return 0;
}

static int __init init_setup(char *str)
{
	unsigned int i;

	execute_command = str;
	/*
	 * In case LILO is going to boot us with default command line,
	 * it prepends "auto" before the whole cmdline which makes
	 * the shell think it should execute a script with such name.
	 * So we ignore all arguments entered _before_ init=... [MJ]
	 */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("init=", init_setup);

static int __init rdinit_setup(char *str)
{
	unsigned int i;

	ramdisk_execute_command = str;
	/* See "auto" comment in init_setup */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("rdinit=", rdinit_setup);

#ifndef CONFIG_SMP
static const unsigned int setup_max_cpus = NR_CPUS;
static inline void setup_nr_cpu_ids(void) { }
static inline void smp_prepare_cpus(unsigned int maxcpus) { }
#endif

/*
 * We need to store the untouched command line for future reference.
 * We also need to store the touched command line since the parameter
 * parsing is performed in place, and we should allow a component to
 * store reference of name/value for future reference.
 *
 * start_kernel()  [init/main.c]
 *  setup_command_line()
 */
static void __init setup_command_line(char *command_line)
{
	saved_command_line =
		memblock_virt_alloc(strlen(boot_command_line) + 1, 0);
	initcall_command_line =
		memblock_virt_alloc(strlen(boot_command_line) + 1, 0);
	static_command_line = memblock_virt_alloc(strlen(command_line) + 1, 0);
	strcpy(saved_command_line, boot_command_line);
	strcpy(static_command_line, command_line);
}

/*
 * We need to finalize in a non-__init function or else race conditions
 * between the root thread and the init thread may cause start_kernel to
 * be reaped by free_initmem before the root thread has proceeded to
 * cpu_idle.
 *
 * gcc-3.4 accidentally inlines this function, so use noinline.
 */

static __initdata DECLARE_COMPLETION(kthreadd_done);

/*
 * start_kernle() [init/main.c]
 *  rest_init()
 *
 * 这个函数创建kernel_init,kthreadd两个内核线程
 */
static noinline void __ref rest_init(void)
{
	struct task_struct *tsk;
	int pid;

	rcu_scheduler_starting();
	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 *
	 * 调用do_basic_setup,执行各种__init函数
	 */
	pid = kernel_thread(kernel_init, NULL, CLONE_FS);
	/*
	 * Pin init on the boot CPU. Task migration is not properly working
	 * until sched_init_smp() has been run. It will set the allowed
	 * CPUs for init to the non isolated CPUs.
	 */
	rcu_read_lock();
	tsk = find_task_by_pid_ns(pid, &init_pid_ns);
	set_cpus_allowed_ptr(tsk, cpumask_of(smp_processor_id()));
	rcu_read_unlock();

	numa_default_policy();
	pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);
	rcu_read_lock();
	kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
	rcu_read_unlock();

	/*
	 * Enable might_sleep() and smp_processor_id() checks.
	 * They cannot be enabled earlier because with CONFIG_PREEMPT=y
	 * kernel_thread() would trigger might_sleep() splats. With
	 * CONFIG_PREEMPT_VOLUNTARY=y the init task might have scheduled
	 * already, but it's stuck on the kthreadd_done completion.
	 */
	system_state = SYSTEM_SCHEDULING;

	complete(&kthreadd_done);

	/*
	 * The boot idle thread must execute schedule()
	 * at least once to get things moving:
	 */
	schedule_preempt_disabled();
	/* Call into cpu_idle with preempt disabled */
	cpu_startup_entry(CPUHP_ONLINE);
}

/* Check for early params. */
static int __init do_early_param(char *param, char *val,
				 const char *unused, void *arg)
{
	const struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {
		if ((p->early && parameq(param, p->str)) ||
		    (strcmp(param, "console") == 0 &&
		     strcmp(p->str, "earlycon") == 0)
		) {
			if (p->setup_func(val) != 0)
				pr_warn("Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	return 0;
}

/*
 * start_kernel()  [init/main.c]
 *  parse_early_param()
 *   parse_early_options()
 */
void __init parse_early_options(char *cmdline)
{
	parse_args("early options", cmdline, NULL, 0, 0, 0, NULL,
		   do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. 
 *
 * start_kernel()  [init/main.c]
 *  parse_early_param()
 */
void __init parse_early_param(void)
{
	static int done __initdata;
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;

	if (done)
		return;

	/* All fall through to do_early_param. */
	strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	parse_early_options(tmp_cmdline);
	done = 1;
}

void __init __weak arch_post_acpi_subsys_init(void) { }

void __init __weak smp_setup_processor_id(void)
{
}

# if THREAD_SIZE >= PAGE_SIZE
void __init __weak thread_stack_cache_init(void)
{
}
#endif

void __init __weak mem_encrypt_init(void) { }

bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

#ifdef TRACEPOINTS_ENABLED
static void __init initcall_debug_enable(void);
#else
static inline void initcall_debug_enable(void)
{
}
#endif

/*
 * Set up kernel memory allocators
 *
 * start_kernel()  [init/main.c]
 *  mm_init()
 */
static void __init mm_init(void)
{
	/*
	 * page_ext requires contiguous pages,
	 * bigger than MAX_ORDER unless SPARSEMEM.
	 */
	//空函数
	page_ext_init_flatmem();

	//这里相当于建立buddy system了
	mem_init();
	
	kmem_cache_init();
	pgtable_init();
	
	vmalloc_init();
	ioremap_huge_init();
	/* Should be run before the first non-init thread is created */
	init_espfix_bsp();
	/* Should be run after espfix64 is set up.
	 *
	 * pti 就是page table isolation的意思了
	 */
	pti_init();
}

/*
 * 从 arch/x86/boot/header.S中的_start 开始，
 * 到 arxh/x86/boot/main.c 中的main 初始化参数，
 * 再到 arxh/x86/boot/pm.c 中的 go_to_protected_mode 跳转到 arch/x86/boot/pmjump.S 中的 protected_mode_jump 进入保护模式，
 * 然后载入 vmlinuz 并自解压，
 * 在 startup_32.S 中开启分页机制、初始化中断向量表、检测 CPU 类型等，完成 x86 体系结构的保护模式初始化
 *
 * secondary_startup_64() at arch/x86/kernel/head_64.S
 *  start_kernel()
 *
 * _start() [arch/x86/boot/header.S]
 *  start_of_setup() [arch/x86/boot/header.S]
 *   main()  [arxh/x86/boot/main.c]
 *    go_to_protected_mode() [arxh/x86/boot/pm.c]
 * 	   protected_mode_jump() [arch/x86/boot/pmjump.S] 实模式
 * 	    in_pm32() [arch/x86/boot/pmjump.S] 保护模式
 * 	     startup_32 [arch/x86/boot/compressed/head_64.S]  compressed目录中的在链接的时候会与vmlinux.bin.gz一起打包成vmlinux.bin,compressed目录中的内容没有被compressed
 * 	      startup_64 [arch/x86/boot/compressed/head_64.S] 已经进入64位模式了
 * 		   relocated 这个是从startup_64()中jmp过来的,这里调用extract_kernel来解压vmlinux.bin.gz
 *
 * 		    startup_64() [arch/x86/kernel/head_64.S]  这个是vmlinux的入口，位于0x1000000 
 *           secondary_startup_64() [arch/x86/kernel/head_64.S] 从startup_64中jump过来的
 * 		      Ljump_to_C_code() [arch/x86/kernel/head_64.S]
 *             x86_64_start_kernel() [arch/x86/kernel/head64.c]
 *              x86_64_start_reservations() [arch/x86/kernel/head64.c]
 *               start_kernel()
 * 
 * 到这个函数的时候，已经进入保护模式了
 *
 */
asmlinkage __visible void __init start_kernel(void)
{
	char *command_line;
	char *after_dashes;


	//设置init_task的内核态stack
	set_task_stack_end_magic(&init_task);

	//x64中为空函数
	smp_setup_processor_id();

	//空函数
	debug_objects_early_init();

    // kernel/cgroup/cgroup.c中
	cgroup_init_early();


	//关中断
	local_irq_disable();
	early_boot_irqs_disabled = true;

	/*
	 * Interrupts are still disabled. Do necessary setups, then
	 * enable them.
	 * 标记当前cpu在 __cpu_online_mask ,__cpu_active_mask ,
	 *               __cpu_present_mask, __cpu_possible_mask中的值
	 */
	boot_cpu_init();

	//初始化page_address_htable[], 这个表应该是在 kmap会用到,vmalloc 不会用到
	page_address_init();
	
	pr_notice("%s", linux_banner);

	//memblock初始化
	setup_arch(&command_line);
	/*
	 * Set up the the initial canary and entropy after arch
	 * and after adding latent and command line entropy.
	 *
	 * 空函数
	 */
	add_latent_entropy();
	
	add_device_randomness(command_line, strlen(command_line));


	/*
	 * 计算出irq_stack_union.stack_canary
	 */
	boot_init_stack_canary();
	
	mm_init_cpumask(&init_mm);
	//复制command_line到saved_command_line
	setup_command_line(command_line);

	//空函数
	setup_nr_cpu_ids();
	
	setup_per_cpu_areas();

	//根据cpu id装载gdt
	smp_prepare_boot_cpu();	/* arch-specific boot-cpu hooks */
	boot_cpu_hotplug_init();
    //建立pg_data->nodezone_lists[].zoneref
	build_all_zonelists(NULL);
	
	page_alloc_init();

	pr_notice("Kernel command line: %s\n", boot_command_line);
	
	parse_early_param();
	after_dashes = parse_args("Booting kernel",
				  static_command_line, __start___param,
				  __stop___param - __start___param,
				  -1, -1, NULL, &unknown_bootoption);
	if (!IS_ERR_OR_NULL(after_dashes))
		parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,
			   NULL, set_init_arg);

    //在jump_label.h中
	jump_label_init();

	/*
	 * These use large bootmem allocations and must precede
	 * kmem_cache_init()
	 *
	 * 从memblock中分配
	 */
	setup_log_buf(0);

	//初始化dentry_hashtable, inode_hashtable
	vfs_caches_init_early();
	
	sort_main_extable();

	/* 在arch/x86/kernel/traps.c中
	 * 设置中断处理函数和内部异常处理函数
	 */
	trap_init();

	/*
	 * 这个函数结束 slab allocator已经建立好了,
	 * 替换掉memblock allocator了
	 */
	mm_init();
	

	ftrace_init();

	/* trace_printk can be enabled here 
	 *  
	 * 分配trace buffer,设置global_trace对象
	 */
	early_trace_init();

	/*
	 * Set up the scheduler prior starting any interrupts (such as the
	 * timer interrupt). Full topology setup happens at smp_init()
	 * time - but meanwhile we still have a functioning scheduler.
	 *
	 * 初始化root_task_group和rq
	 */
	sched_init();
	/*
	 * Disable preemption - early bootup scheduling is extremely
	 * fragile until we cpu_idle() for the first time.
	 */
	preempt_disable();
	if (WARN(!irqs_disabled(),
		 "Interrupts were enabled *very* early, fixing it\n"))
		local_irq_disable();

	//分配radix_tree_noce_cachep
	radix_tree_init();

	/*
	 * Set up housekeeping before setting up workqueues to allow the unbound
	 * workqueue to take non-housekeeping into account.
	 *
	 * 在isolation.c中
	 */
	housekeeping_init();

	/*
	 * Allow workqueue creation and work item queueing/cancelling
	 * early.  Work item execution depends on kthreads and starts after
	 * workqueue_init().
	 */
	workqueue_init_early();

    /*
     * 初始化rcu_bh_state, rcu_sched_state, rcu_gq_wq, rcu_par_gp_wq
     */
	rcu_init();

	/* Trace events are available after this 
	 *
	 * event trace, syscalls trace 这些功能
	 */
	trace_init();

	if (initcall_debug) //默认为0
		initcall_debug_enable(); //空函数

    //空函数
	context_tracking_init();
	/* init some links before init_ISA_irqs() 
	 * 在irqdesc.c中
	 * 分配irq_desc对象,
	 */
	early_irq_init();

	/* idt_setup_apic_and_irq_gates()中 设置中断处理函数，比如
	 * RESCHEDULE_VECTOR  -->  reschedule_interrupt
     * LOCAL_TIMER_VECTOR -->  apic_timer_interrupt
	 */
	init_IRQ();
	
	tick_init();
	
	rcu_init_nohz();
	//设置TIMER_SOFTIRQ 回调函数为run_timer_softirq
	init_timers();
	//设置HRTIMER_SOFTIRQ 回调函数为 hrtimer_run_softirq
	hrtimers_init();

	//初始化tasklet_vec,tasklet_hi_vec
	softirq_init();
	
	timekeeping_init();
	//设置late_time_init == x86_late_time_init
	time_init();

	//跳过，不看
	printk_safe_init();
	
	perf_event_init();
	
	profile_init();
	
	call_function_init();
	WARN(!irqs_disabled(), "Interrupts were enabled early\n");

	early_boot_irqs_disabled = false;
	local_irq_enable();

    //走到slab_state == FULL状态
	kmem_cache_init_late();

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	console_init();
	if (panic_later)
		panic("Too many boot %s vars at `%s'", panic_later,
		      panic_param);

	lockdep_init();

	/*
	 * Need to run this when irqs are enabled, because it wants
	 * to self-test [hard/soft]-irqs on/off lock inversion bugs
	 * too:
	 */
	locking_selftest();

	/*
	 * This needs to be called before any devices perform DMA
	 * operations that might use the SWIOTLB bounce buffers. It will
	 * mark the bounce buffers as decrypted so that their usage will
	 * not cause "plain-text" data to be decrypted when accessed.
	 */
	mem_encrypt_init();

//有定义
#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_start && !initrd_below_start_ok &&
	    page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
		pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
		    page_to_pfn(virt_to_page((void *)initrd_start)),
		    min_low_pfn);
		initrd_start = 0;
	}
#endif

    //在page_ext.c中
	page_ext_init();

    //空函数
	kmemleak_init();
	//空函数
	debug_objects_mem_init();

	//设置zone->pageset
	setup_per_cpu_pageset();
	
	numa_policy_init();
	acpi_early_init();

	/*
	 * late_time_init == x86_late_time_init
	 * 会调用setup_local_APIC,setup_IO_APIC
	*/
	if (late_time_init)
		late_time_init();
	
	sched_clock_init();
	calibrate_delay();
	//初始化 init_pid_ns
	pid_idr_init();
	//创建anon_vma_cachep
	anon_vma_init();
#ifdef CONFIG_X86
	if (efi_enabled(EFI_RUNTIME_SERVICES))
		efi_enter_virtual_mode();
#endif

    //空函数
	thread_stack_cache_init();

    //创建cred_jar
	cred_init();
	//初始化init_task.signal->rlim[]
	fork_init();

	/*
	 * 创建sighand_cachep, signal_cachep, files_cachep,
	 *     fs_cachep, mm_cachep, vm_area_cachep, nsproxy_cachep对象
	 */
	proc_caches_init();

	//创建uts_ns_cache对象
	uts_ns_init();

	//创建bh_cachep，用于分配buffer_head对象,挂载根文件系统rootfs_fs_type,设置当前进程的root目录
	buffer_init();
	//键盘
	key_init();
	security_init();

	//空函数
	dbg_late_init();
	/*
	 * 创建了很多kmem_cache对象
	 * 挂载rootfs_fs_type, bd_type
	 */
	vfs_caches_init();
	//page_wait_table[]初始化
	pagecache_init();
	//到这里
	signals_init();
	seq_file_init();

	//初始化proc文件系统
	proc_root_init();

	//namespace filesystem
	nsfs_init();
	
	cpuset_init();
	
	cgroup_init();
	
	taskstats_init_early();
	delayacct_init();

    //硬件检查
	check_bugs();

	acpi_subsystem_init();

	//空函数
	arch_post_acpi_subsys_init();

	//sfi == Simple Firmware Interface
	sfi_init_late();

	if (efi_enabled(EFI_RUNTIME_SERVICES)) {
		efi_free_boot_services();
	}

	/* Do the rest non-__init'ed, we're now alive */
	rest_init();
}

/* Call all constructor functions linked into the kernel. */
static void __init do_ctors(void)
{
#ifdef CONFIG_CONSTRUCTORS
	ctor_fn_t *fn = (ctor_fn_t *) __ctors_start;

	for (; fn < (ctor_fn_t *) __ctors_end; fn++)
		(*fn)();
#endif
}

#ifdef CONFIG_KALLSYMS
struct blacklist_entry {
	struct list_head next;
	char *buf;
};

static __initdata_or_module LIST_HEAD(blacklisted_initcalls);

static int __init initcall_blacklist(char *str)
{
	char *str_entry;
	struct blacklist_entry *entry;

	/* str argument is a comma-separated list of functions */
	do {
		str_entry = strsep(&str, ",");
		if (str_entry) {
			pr_debug("blacklisting initcall %s\n", str_entry);
			entry = alloc_bootmem(sizeof(*entry));
			entry->buf = alloc_bootmem(strlen(str_entry) + 1);
			strcpy(entry->buf, str_entry);
			list_add(&entry->next, &blacklisted_initcalls);
		}
	} while (str_entry);

	return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	struct blacklist_entry *entry;
	char fn_name[KSYM_SYMBOL_LEN];
	unsigned long addr;

	if (list_empty(&blacklisted_initcalls))
		return false;

	addr = (unsigned long) dereference_function_descriptor(fn);
	sprint_symbol_no_offset(fn_name, addr);

	/*
	 * fn will be "function_name [module_name]" where [module_name] is not
	 * displayed for built-in init functions.  Strip off the [module_name].
	 */
	strreplace(fn_name, ' ', '\0');

	list_for_each_entry(entry, &blacklisted_initcalls, next) {
		if (!strcmp(fn_name, entry->buf)) {
			pr_debug("initcall %s blacklisted\n", fn_name);
			return true;
		}
	}

	return false;
}
#else
static int __init initcall_blacklist(char *str)
{
	pr_warn("initcall_blacklist requires CONFIG_KALLSYMS\n");
	return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	return false;
}
#endif
__setup("initcall_blacklist=", initcall_blacklist);

static __init_or_module void
trace_initcall_start_cb(void *data, initcall_t fn)
{
	ktime_t *calltime = (ktime_t *)data;

	printk(KERN_DEBUG "calling  %pF @ %i\n", fn, task_pid_nr(current));
	*calltime = ktime_get();
}

static __init_or_module void
trace_initcall_finish_cb(void *data, initcall_t fn, int ret)
{
	ktime_t *calltime = (ktime_t *)data;
	ktime_t delta, rettime;
	unsigned long long duration;

	rettime = ktime_get();
	delta = ktime_sub(rettime, *calltime);
	duration = (unsigned long long) ktime_to_ns(delta) >> 10;
	printk(KERN_DEBUG "initcall %pF returned %d after %lld usecs\n",
		 fn, ret, duration);
}

static ktime_t initcall_calltime;

#ifdef TRACEPOINTS_ENABLED
static void __init initcall_debug_enable(void)
{
	int ret;

	ret = register_trace_initcall_start(trace_initcall_start_cb,
					    &initcall_calltime);
	ret |= register_trace_initcall_finish(trace_initcall_finish_cb,
					      &initcall_calltime);
	WARN(ret, "Failed to register initcall tracepoints\n");
}
# define do_trace_initcall_start	trace_initcall_start
# define do_trace_initcall_finish	trace_initcall_finish
#else
static inline void do_trace_initcall_start(initcall_t fn)
{
	if (!initcall_debug)
		return;
	trace_initcall_start_cb(&initcall_calltime, fn);
}
static inline void do_trace_initcall_finish(initcall_t fn, int ret)
{
	if (!initcall_debug)
		return;
	trace_initcall_finish_cb(&initcall_calltime, fn, ret);
}
#endif /* !TRACEPOINTS_ENABLED */

/*
 * start_kernle() [init/main.c]
 *  rest_init()
 *   ......
 *    kernel_init()
 *     kernel_init_freeable()
 *      do_pre_smp_initcalls()
 *       do_one_initcall()
 */
int __init_or_module do_one_initcall(initcall_t fn)
{
	int count = preempt_count();
	char msgbuf[64];
	int ret;

	if (initcall_blacklisted(fn))
		return -EPERM;

	do_trace_initcall_start(fn);
	ret = fn();
	do_trace_initcall_finish(fn, ret);

	msgbuf[0] = 0;

	if (preempt_count() != count) {
		sprintf(msgbuf, "preemption imbalance ");
		preempt_count_set(count);
	}
	if (irqs_disabled()) {
		strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
		local_irq_enable();
	}
	WARN(msgbuf[0], "initcall %pF returned with %s\n", fn, msgbuf);

	add_latent_entropy();
	return ret;
}


extern initcall_entry_t __initcall_start[];
extern initcall_entry_t __initcall0_start[];
extern initcall_entry_t __initcall1_start[];
extern initcall_entry_t __initcall2_start[];
extern initcall_entry_t __initcall3_start[];
extern initcall_entry_t __initcall4_start[];
extern initcall_entry_t __initcall5_start[];
extern initcall_entry_t __initcall6_start[];
extern initcall_entry_t __initcall7_start[];
extern initcall_entry_t __initcall_end[];

static initcall_entry_t *initcall_levels[] __initdata = {
	__initcall0_start,
	__initcall1_start,
	__initcall2_start,
	__initcall3_start,
	__initcall4_start,
	__initcall5_start,
	__initcall6_start,
	__initcall7_start,
	__initcall_end,
};

/* Keep these in sync with initcalls in include/linux/init.h */
static char *initcall_level_names[] __initdata = {
	"pure",
	"core",
	"postcore",
	"arch",
	"subsys",
	"fs",
	"device",
	"late",
};

/*
 * start_kernel()
 *  do_basic_setup()
 *   do_initcalls()
 *    do_initcall_level()
 */
static void __init do_initcall_level(int level)
{
	initcall_entry_t *fn;

	strcpy(initcall_command_line, saved_command_line);
	parse_args(initcall_level_names[level],
		   initcall_command_line, __start___param,
		   __stop___param - __start___param,
		   level, level,
		   NULL, &repair_env_string);

	trace_initcall_level(initcall_level_names[level]);
	for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++)
		do_one_initcall(initcall_from_entry(fn));
}

/*
 * start_kernel()
 *  do_basic_setup()
 *   do_initcalls()
 */
static void __init do_initcalls(void)
{
	int level;

    /*
     *
     * 
     *
     * 1. core_initcall(ksysfs_init)
     * 1. core_initcall(sock_init)
     * 1. core_initcall(init_zero_pfn)
     * 1. core_initcall(cgroup_wq_init)
     * 1. core_initcall(init_zero_pfn)
     * 1. core_initcall(virtio_init)   //注册virtio_bus,bus_register(&virtio_bus)
     * 1. core_initcall(dma_init_reserved_memory)
     * 1. core_initcall(netlink_proto_init)
     *
     * 2. postcore_initcall()
     *
     * 3. arch_initcall(bts_init) perf性能监控使用
     * 3. arch_initcall(activate_jump_labels)
     * 3. arch_initcall(kvm_setup_pv_tlb_flush)
     * 3. arch_initcall(pci_arch_init)  
     *
     * 4. subsys_initcall(cgroup_sysfs_init)
     * 4. subsys_initcall(cgroup_namespaces_init)     
     * 4. subsys_initcall(mem_cgroup_init)
     * 4. subsys_initcall(mem_cgroup_swap_init)     
     * 4. subsys_initcall(init_user_reserve)
     * 4. subsys_initcall(ksm_init)
     * 4. subsys_initcall(pktsched_init)
     * 4. subsys_initcall(pci_subsys_init)  完成pci总线树的枚举和配置
     *
     *
     * 5. fs_initcall(inet_init)
     * 5. fs_initcall(pcibios_assign_resources) //pci域的地址信息写入到设备配置空间的bar中
     * 
     * 
     * 6. __initcall(cpucache_init)
     * 6. __initcall(memblock_init_debugfs)
     *
     * 6. module_init(init_kprobes)
     * 6. module_init(tun_init)
     * 
     * 6. module_init(br_init)
     * 6. module_init(tun_init)
     *
     * 6. module_pci_driver(virtio_pci_driver)
     * 6. module_virtio_driver(virtio_balloon_driver)
     *
     * 6. module_init(virtio_net_driver_init)
     * 6. module_init(vhost_init)
     * 6. module_init(vhost_net_init)
     *
     * 6. module_init(e1000_init_module) e1000e网卡驱动
     *
     * 6. rootfs_initcall(populate_rootfs) ,会调用 populate_rootfs,
     * 6. rootfs_initcall(pci_iommu_init) 
     *
     * 7. late_initcall(debugfs_kprobe_init)
     *
     * 
     */
	for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++)
		do_initcall_level(level);
}

/*
 * Ok, the machine is now initialized. None of the devices
 * have been touched yet, but the CPU subsystem is up and
 * running, and memory and process management works.
 *
 * Now we can finally start doing some real work..
 *
 * start_kernel()
 *  do_basic_setup()
 */
static void __init do_basic_setup(void)
{
    //设置top_cpuset
	cpuset_init_smp();
	
	shmem_init();
	
	driver_init();
	init_irq_proc();
	do_ctors();
	usermodehelper_enable();
	
	do_initcalls();
}

/*
 * start_kernle() [init/main.c]
 *  rest_init()
 *   ......
 *    kernel_init()
 *     kernel_init_freeable()
 *      do_pre_smp_initcalls()
 */
static void __init do_pre_smp_initcalls(void)
{
	initcall_entry_t *fn;

	trace_initcall_level("early");
	for (fn = __initcall_start; fn < __initcall0_start; fn++)
		do_one_initcall(initcall_from_entry(fn));
}

/*
 * This function requests modules which should be loaded by default and is
 * called twice right after initrd is mounted and right before init is
 * exec'd.  If such modules are on either initrd or rootfs, they will be
 * loaded before control is passed to userland.
 *
 * start_kernle() [init/main.c]
 *  rest_init()
 *   ......
 *    kernel_init()
 *     kernel_init_freeable()
 *      load_default_modules()
 *
 * start_kernle() [init/main.c]
 *  rest_init()
 *   ......
 *    kernel_init()
 *     kernel_init_freeable()
 *      prepare_namespace()
 *       initrd_load()
 *        handle_initrd()
 *         load_default_modules()
 */
void __init load_default_modules(void)
{
   load_default_elevator_module();
}

static int run_init_process(const char *init_filename)
{
	argv_init[0] = init_filename;
	pr_info("Run %s as init process\n", init_filename);
	return do_execve(getname_kernel(init_filename),
		(const char __user *const __user *)argv_init,
		(const char __user *const __user *)envp_init);
}

static int try_to_run_init_process(const char *init_filename)
{
	int ret;

	ret = run_init_process(init_filename);

	if (ret && ret != -ENOENT) {
		pr_err("Starting init: %s exists but couldn't execute it (error %d)\n",
		       init_filename, ret);
	}

	return ret;
}



static noinline void __init kernel_init_freeable(void);

//有定义
#if defined(CONFIG_STRICT_KERNEL_RWX) || defined(CONFIG_STRICT_MODULE_RWX)
bool rodata_enabled __ro_after_init = true;
static int __init set_debug_rodata(char *str)
{
	return strtobool(str, &rodata_enabled);
}
__setup("rodata=", set_debug_rodata);
#endif

//有定义
#ifdef CONFIG_STRICT_KERNEL_RWX
static void mark_readonly(void)
{
	if (rodata_enabled) {
		/*
		 * load_module() results in W+X mappings, which are cleaned up
		 * with call_rcu_sched().  Let's make sure that queued work is
		 * flushed so that we don't hit false positives looking for
		 * insecure pages which are W+X.
		 */
		rcu_barrier_sched();
		mark_rodata_ro();
		rodata_test();
	} else
		pr_info("Kernel memory protection disabled.\n");
}
#else
static inline void mark_readonly(void)
{
	pr_warn("This architecture does not have kernel memory protection.\n");
}
#endif

/*
 * start_kernle() [init/main.c]
 *  rest_init()
 *   ......
 *    kernel_init()
 *
 * kernel_init是 1号进程，init进程，用户态进程
 */
static int __ref kernel_init(void *unused)
{
	int ret;

    //启动secondary cpu
	kernel_init_freeable();
	/* need to finish all async __init code before freeing the memory */
	async_synchronize_full();
	ftrace_free_init_mem();
	//空函数
	jump_label_invalidate_initmem();
	//释放 __init标记的代码
	free_initmem();
	mark_readonly();

	/*
	 * Kernel mappings are now finalized - update the userspace page-table
	 * to finalize PTI.
	 */
	pti_finalize();

	system_state = SYSTEM_RUNNING;
	numa_default_policy();

	rcu_end_inkernel_boot();

   // rdinit= 字符串
	if (ramdisk_execute_command) {
		ret = run_init_process(ramdisk_execute_command);
		if (!ret)
			return 0;
		pr_err("Failed to execute %s (error %d)\n",
		       ramdisk_execute_command, ret);
	}

	/*
	 * We try each of these until one succeeds.
	 *
	 * The Bourne shell can be used instead of init if we are
	 * trying to recover a really broken machine.
	 */
	if (execute_command) {
		ret = run_init_process(execute_command);
		if (!ret)
			return 0;
		panic("Requested init %s failed (error %d).",
		      execute_command, ret);
	}
	if (!try_to_run_init_process("/sbin/init") ||
	    !try_to_run_init_process("/etc/init") ||
	    !try_to_run_init_process("/bin/init") ||
	    !try_to_run_init_process("/bin/sh"))
		return 0;

	panic("No working init found.  Try passing init= option to kernel. "
	      "See Linux Documentation/admin-guide/init.rst for guidance.");
}

/*
 * 
 * start_kernle() [init/main.c]
 *  rest_init()
 *   ......
 *    kernel_init()
 *     kernel_init_freeable()
 */
static noinline void __init kernel_init_freeable(void)
{
	/*
	 * Wait until kthreadd is all set-up.
	 */
	wait_for_completion(&kthreadd_done);

	/* Now the scheduler is fully set up and can do blocking allocations */
	gfp_allowed_mask = __GFP_BITS_MASK;


	/*
	 * init can allocate pages on any node
	 */
	set_mems_allowed(node_states[N_MEMORY]);

	cad_pid = task_pid(current);

    /*
     * 重要
     * x86/include/asm/smp.h中
     */
	smp_prepare_cpus(setup_max_cpus);

	workqueue_init();

	init_mm_internals();

    //调用__initcall0之前的 
	do_pre_smp_initcalls();
	//死锁检测
	lockup_detector_init();


    // 启动 secondary cpus
	smp_init();

	//创建CPU拓扑关系
	sched_init_smp();

	page_alloc_init_late();

    //这个内容很丰富了,调用各种__init函数
	do_basic_setup();

	/* Open the /dev/console on the rootfs, this should never fail */
	if (ksys_open((const char __user *) "/dev/console", O_RDWR, 0) < 0)
		pr_err("Warning: unable to open an initial console.\n");

	(void) ksys_dup(0);
	(void) ksys_dup(0);
	/*
	 * check if there is an early userspace init.  If yes, let it do all
	 * the work
	 */

	if (!ramdisk_execute_command)
		ramdisk_execute_command = "/init";

	if (ksys_access((const char __user *)
			ramdisk_execute_command, 0) != 0) {
		ramdisk_execute_command = NULL;

		//挂载根文件系统，特别注意mount namespace,这个对容器很重要
		prepare_namespace();
	}

	/*
	 * Ok, we have completed the initial bootup, and
	 * we're essentially up and running. Get rid of the
	 * initmem segments and start the user-mode stuff..
	 *
	 * rootfs is available now, try loading the public keys
	 * and default modules
	 *
	 *
	 */

	integrity_load_keys();
	load_default_modules();
}
