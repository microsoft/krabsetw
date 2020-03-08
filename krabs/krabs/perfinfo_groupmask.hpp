// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

// https://geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracesup/perfinfo_groupmask.htm

struct PERFINFO_GROUPMASK
{
    ULONG Masks[8];
};

// Masks[0]
#define PERF_PROCESS            0x00000001
#define PERF_THREAD             0x00000002
#define PERF_PROC_THREAD        0x00000003
#define PERF_LOADER             0x00000004
#define PERF_PERF_COUNTER       0x00000008
#define PERF_FILENAME           0x00000200
#define PERF_DISK_IO            0x00000300
#define PERF_DISK_IO_INIT       0x00000400
#define PERF_ALL_FAULTS         0x00001000
#define PERF_HARD_FAULTS        0x00002000
#define PERF_VAMAP              0x00008000
#define PERF_NETWORK            0x00010000
#define PERF_REGISTRY           0x00020000
#define PERF_DBGPRINT           0x00040000
#define PERF_JOB                0x00080000
#define PERF_ALPC               0x00100000
#define PERF_SPLIT_IO           0x00200000
#define PERF_DEBUG_EVENTS       0x00400000
#define PERF_FILE_IO            0x02000000
#define PERF_FILE_IO_INIT       0x04000000
#define PERF_NO_SYSCONFIG       0x10000000

// Masks[1]
#define PERF_MEMORY             0x20000001
#define PERF_PROFILE            0x20000002
#define PERF_CONTEXT_SWITCH     0x20000004
#define PERF_FOOTPRINT          0x20000008
#define PERF_DRIVERS            0x20000010
#define PERF_REFSET             0x20000020
#define PERF_POOL               0x20000040
#define PERF_POOLTRACE          0x20000041
#define PERF_DPC                0x20000080
#define PERF_COMPACT_CSWITCH    0x20000100
#define PERF_DISPATCHER         0x20000200
#define PERF_PMC_PROFILE        0x20000400
#define PERF_PROFILING          0x20000402
#define PERF_PROCESS_INSWAP     0x20000800
#define PERF_AFFINITY           0x20001000
#define PERF_PRIORITY           0x20002000
#define PERF_INTERRUPT          0x20004000
#define PERF_VIRTUAL_ALLOC      0x20008000
#define PERF_SPINLOCK           0x20010000
#define PERF_SYNC_OBJECTS       0x20020000
#define PERF_DPC_QUEUE          0x20040000
#define PERF_MEMINFO            0x20080000
#define PERF_CONTMEM_GEN        0x20100000
#define PERF_SPINLOCK_CNTRS     0x20200000
#define PERF_SPININSTR          0x20210000
#define PERF_SESSION            0x20400000
#define PERF_PFSECTION          0x20400000
#define PERF_MEMINFO_WS         0x20800000
#define PERF_KERNEL_QUEUE       0x21000000
#define PERF_INTERRUPT_STEER    0x22000000
#define PERF_SHOULD_YIELD       0x24000000
#define PERF_WS                 0x28000000

// Masks[2]
#define PERF_ANTI_STARVATION    0x40000001
#define PERF_PROCESS_FREEZE     0x40000002
#define PERF_PFN_LIST           0x40000004
#define PERF_WS_DETAIL          0x40000008
#define PERF_WS_ENTRY           0x40000010
#define PERF_HEAP               0x40000020
#define PERF_SYSCALL            0x40000040
#define PERF_UMS                0x40000080
#define PERF_BACKTRACE          0x40000100
#define PERF_VULCAN             0x40000200
#define PERF_OBJECTS            0x40000400
#define PERF_EVENTS             0x40000800
#define PERF_FULLTRACE          0x40001000
#define PERF_DFSS               0x40002000
#define PERF_PREFETCH           0x40004000
#define PERF_PROCESSOR_IDLE     0x40008000
#define PERF_CPU_CONFIG         0x40010000
#define PERF_TIMER              0x40020000
#define PERF_CLOCK_INTERRUPT    0x40040000
#define PERF_LOAD_BALANCER      0x40080000
#define PERF_CLOCK_TIMER        0x40100000
#define PERF_IDLE_SELECTION     0x40200000
#define PERF_IPI                0x40400000
#define PERF_IO_TIMER           0x40800000
#define PERF_REG_HIVE           0x41000000
#define PERF_REG_NOTIF          0x42000000
#define PERF_PPM_EXIT_LATENCY   0x44000000
#define PERF_WORKER_THREAD      0x48000000

// Masks[4]
#define PERF_OPTICAL_IO         0x80000001
#define PERF_OPTICAL_IO_INIT    0x80000002
#define PERF_DLL_INFO           0x80000008
#define PERF_DLL_FLUSH_WS       0x80000010
#define PERF_OB_HANDLE          0x80000040
#define PERF_OB_OBJECT          0x80000080
#define PERF_WAKE_DROP          0x80000200
#define PERF_WAKE_EVENT         0x80000400
#define PERF_DEBUGGER           0x80000800
#define PERF_PROC_ATTACH        0x80001000
#define PERF_WAKE_COUNTER       0x80002000
#define PERF_POWER              0x80008000
#define PERF_SOFT_TRIM          0x80010000
#define PERF_CC                 0x80020000
#define PERF_FLT_IO_INIT        0x80080000
#define PERF_FLT_IO             0x80100000
#define PERF_FLT_FASTIO         0x80200000
#define PERF_FLT_IO_FAILURE     0x80400000
#define PERF_HV_PROFILE         0x80800000
#define PERF_WDF_DPC            0x81000000
#define PERF_WDF_INTERRUPT      0x82000000
#define PERF_CACHE_FLUSH        0x84000000

// Masks[5]
#define PERF_HIBER_RUNDOWN      0xA0000001

// Masks[6]
#define PERF_SYSCFG_SYSTEM      0xC0000001
#define PERF_SYSCFG_GRAPHICS    0xC0000002
#define PERF_SYSCFG_STORAGE     0xC0000004
#define PERF_SYSCFG_NETWORK     0xC0000008
#define PERF_SYSCFG_SERVICES    0xC0000010
#define PERF_SYSCFG_PNP         0xC0000020
#define PERF_SYSCFG_OPTICAL     0xC0000040
#define PERF_SYSCFG_ALL         0xDFFFFFFF

// Masks[7]
#define PERF_CLUSTER_OFF        0xE0000001
#define PERF_MEMORY_CONTROL     0xE0000002