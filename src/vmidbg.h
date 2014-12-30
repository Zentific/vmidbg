/* Copyright 2014 Steven Maresca/Zentific LLC */

#ifndef VMIDBG_H
#define VMIDBG_H
#define _GNU_SOURCE

#include <assert.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <errno.h>
#include <glib.h>

#include <unistd.h> // for read() only now used by only full_packet()

#include <libvmi/libvmi.h>

typedef enum {
    INVALID_STUB,
    GDB_STUB,
    WINDBG_STUB,
    STUB_MAX
} server_modes;

#define ERRIF(x, err) \
    if (x) { \
        char strerr[BUFSIZ]; \
        if(errno) { \
            strerror_r(errno, strerr, BUFSIZ); \
        } \
        fprintf(stderr, "ERROR %s - see %s() at line %d.\n", \
            strerr, __FUNCTION__, __LINE__); \
        goto err; \
    }

typedef struct {
    /* gdb stub server info */
    int sock_fd;
    int client_fd;
    FILE *client_fp;
    char client_ip[INET_ADDRSTRLEN];
    uint16_t client_port;

    /* VM and LibVMI info */
    vmi_instance_t vmi;
    vmi_event_t *int3_event; 
    GHashTable *bp_lookup;
    int pause_at_init;
    int vm_paused;
    int vcpus_paused;

    /* gdb mode info */
    int multiprocess_extended;
    int no_ack_mode;
    int non_stop_mode;

    /* debugger mode: 0 == monitoring a particular pid, 1 == kernel-wide  
     *  affects thread lists
     */
    int kernel_perspective;

    /* 'current' process and thread IDs applying to c/g/s, etc packets */
    uint32_t pid;
    uint32_t tid;
} vmi_dbg_ctx;

typedef enum { 
    VMIDBG_ERROR = -1,
    VMIDBG_SUCCESS,
    VMIDBG_UNIMPLEMENTED,
    __MAX_VMIDBG_STATUS
} vmidbg_status;

struct breakpoint;
typedef struct breakpoint breakpoint_t;
typedef int (*zazen_func)(vmi_instance_t vmi, breakpoint_t *);

struct breakpoint {
    addr_t address;
    uint8_t backup_byte;
    char *name;
    zazen_func callback;
    vmi_event_t *event;
    vmi_pid_t pid;
    int discard;
    vmi_dbg_ctx *ctx;
};

/* ------------------------------------------------------------------------- */
/* ---------------------------- GDB support code --------------------------- */
/* ------------------------------------------------------------------------- */

#define MAX_VMIDBG_PACKET 0x3fff
#define I386_TARGET "<target><architecture>i386</architecture></target>"
#define X86_64_TARGET "<target><architecture>i386:x86-64</architecture></target>"

struct gdb_regs {
    union {
        struct {
            uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;
            uint32_t eip, eflags;
            uint32_t cs, ss, ds, es, fs, gs;
        } regs32;

        struct {
            uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
            uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
            uint64_t rip;
            uint32_t eflags;
            uint32_t cs, ss, ds, es, fs, gs;
        } regs64;
    };
};

/* ------------------------------------------------------------------------- */
/* -------------------------- WinDbg support code -------------------------- */
/* ------------------------------------------------------------------------- */

/* originally defined elsewhere to be USHORT and ULONGs */
typedef struct {
    uint32_t PacketLeader;
    uint8_t PacketType;
    uint8_t ByteCount;
    uint32_t PacketId;
    uint32_t Checksum;
} WINDBG_PACKET;

/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

#endif
