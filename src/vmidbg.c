/* Copyright 2014 Steven Maresca/Zentific LLC */

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
#include "vmidbg.h"

static uint8_t INT3_INSTR = 0xCC;
static int interrupted = 0;

static void close_handler(int sig){
    interrupted = sig;
}

void breakpoint_free(breakpoint_t *b){
    if(b){
        free(b->name);
        /* b->event is only a reference, managed elsewhere.
         *  Don't free it here
         */
        free(b);
    }
}

/* FIXME IMPLEMENT */
GSList * get_all_processes(vmi_dbg_ctx *ctx) {
    GSList * ret = NULL;

    goto fail;
    
    return ret;

fail:
    return NULL;
}

/* FIXME IMPLEMENT */
GSList * get_all_process_threads(vmi_dbg_ctx *ctx) {
    GSList * ret = NULL;
    
    goto fail;

    return ret;

fail:
    return NULL;
}

addr_t get_executing_task(vmi_instance_t vmi, unsigned long vcpu){
    addr_t executing_task = 0;
    static addr_t per_cpu_current_task_offset = 0;
    reg_t base = 0;
    reg_t fs_or_gs = 0;

    //TODO if HVM, try accessing the tr register data. maybe.
    /* see revision 37, line 199: http://code.google.com/p/nitro-kvm/source/browse/trunk/nitro-kmod/x86/syscall_monitor.c */
    if(vmi_get_address_width(vmi) == 8){
        /* 64 bit uses FS for per-cpu variables */
        fs_or_gs = GS_BASE;
    } else {
        /* 32 bit uses FS for per-cpu variables */
        fs_or_gs = FS_BASE;
        /* TODO FIXME needs work for 32bit: necessary to ensure FS is acquired
         *  when CPL=0 for this to be meaningful in a general sense.
         * This function will work ONLY because we're instrumenting kernel functions
         *  in this utility and CPL=0 is an implicit side-effect.
         */
    }

    if(vmi_get_vcpureg (vmi, &base, fs_or_gs, vcpu) == VMI_FAILURE){
        printf("uhoh! reg fetch for fs/gs fail.\n");
    }

    /* offset is for per_cpu__current_task which holds a 
     * pointer to task_struct pointer = gs+offset
     */
    if(!per_cpu_current_task_offset)
        per_cpu_current_task_offset = vmi_translate_ksym2v(vmi, "per_cpu__current_task");
    if(!per_cpu_current_task_offset)
        per_cpu_current_task_offset =  vmi_translate_ksym2v(vmi, "current_task");

    vmi_read_addr_va(vmi, base+per_cpu_current_task_offset, 0, &executing_task);

    return executing_task;
}

vmidbg_status get_connection(vmi_dbg_ctx *ctx) {

    int reuse = 1;
    struct sockaddr_in sockaddr;

    vmidbg_status status = VMIDBG_ERROR;
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    ERRIF(sock_fd == -1, err);

    sockaddr.sin_family = AF_INET;
    /* 127.0.0.1 == 0x7F000001 */
    sockaddr.sin_addr.s_addr = htonl(0x7f000001);

    /* 2159 udp and tcp are the official registered remote debug ports */
    sockaddr.sin_port = htons(2159);

    int rc = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
                    (void *)&reuse, sizeof(reuse));

    ERRIF(rc != 0, err);

    rc = bind(sock_fd, (struct sockaddr *) &sockaddr, sizeof(sockaddr));
    
    ERRIF(rc != 0, err);

    rc = listen(sock_fd, 1);
    
    ERRIF(rc != 0, err);

    ctx->sock_fd = sock_fd;

    return VMIDBG_SUCCESS;

err:
    return status;
}

/* blocking */
vmidbg_status await_client(vmi_dbg_ctx *ctx){

    vmidbg_status status = VMIDBG_ERROR;
    struct sockaddr_in client_addr = {0};
    socklen_t addr_size = sizeof(struct sockaddr);
    memset(&client_addr, 0, sizeof(struct sockaddr_in));
    int clientfd = accept(ctx->sock_fd, (struct sockaddr *)&client_addr, &addr_size);

    ERRIF(clientfd == -1, err);

    struct timeval timeout;      
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int rc = setsockopt (clientfd, SOL_SOCKET, SO_RCVTIMEO,
            (char *)&timeout, sizeof(timeout));

    ERRIF(rc != 0, err);

    rc = setsockopt (clientfd, SOL_SOCKET, SO_SNDTIMEO,
            (char *)&timeout, sizeof(timeout));
    
    ERRIF(rc != 0, err);

    /* preserve file descriptor */
    ctx->client_fd = clientfd;

    /* record remote IP */
    unsigned int len = sizeof(client_addr);
    rc = getpeername(clientfd, (struct sockaddr*) &client_addr, &len);
    
    ERRIF(rc != 0, err);
    
    ctx->client_port = ntohs(client_addr.sin_port);
    inet_ntop(AF_INET, &client_addr.sin_addr, ctx->client_ip, INET_ADDRSTRLEN);

    printf("New connection from %s:%d\n", ctx->client_ip, ctx->client_port);

    /* preserve FILE for stream ops */
    ctx->client_fp = fdopen(clientfd, "w+");
    
    ERRIF(!ctx->client_fp, err);

    return VMIDBG_SUCCESS;

err:
    return status;

}

int hex_to_int(char ch) {
    if ('0' <= ch && ch <= '9') {
        return ch - '0';
    } else if ('a' <= ch && ch <= 'f') {
        return ch - 'a' + 10;
    } else if ('A' <= ch && ch <= 'F') {
        return ch - 'A' + 10;
    } else {
        return 0;
    }
}

void hex_to_mem(uint8_t *mem, const char * buf, int len){
    
    int i;

    for(i = 0; i < len; i++){
        mem[i] = (hex_to_int(buf[0]) << 4) | hex_to_int(buf[1]);
        buf += 2;
    }
}

char int_to_hex(unsigned val) {
//TODO just use array "0123456789abcdef"
// see http://codereview.stackexchange.com/questions/30579/how-can-this-integer-to-hex-string-code-be-improved
    assert(val < 16);
    if (val < 10) {
        return val + '0';
    } else {
        return val - 10 + 'a';
    }
}

void write_hex_byte(char *dest, uint8_t byte) {
    dest[0] = int_to_hex(byte >> 4);
    dest[1] = int_to_hex(byte & 0xf);
}

void write_hex_bytes(char *dest, uint8_t *data, size_t size) {
  size_t index;
  for (index = 0; index < size; index++) {
    write_hex_byte(dest, data[index]);
    dest += 2;
  }
}

char log_getc(FILE *fp) {
   int ch = getc(fp);
    
    /* EAGAIN here because the setsockopt   */ 
    if(errno == EWOULDBLOCK || errno == EAGAIN) return 0;

    /* FIXME, better errno handling
     *  double check EOF behavior around EAGAIN/WOULDBLOCK
     */
    if (ch == EOF) {
#ifdef DEBUG
        fprintf(stderr, "Got EOF\n");
#endif
    }
    return ch;
}


/* TODO FIXME IMPLEMENT
 * note, buffer is probably going to be a structure for windbg
 */
int get_windbg_packet(vmi_dbg_ctx *ctx, char *buffer, int buffer_size) {
    int ret = -1;
    return ret;
}


/* Read a message of the format "$<data>#<checksum>". */
int get_gdb_packet(vmi_dbg_ctx *ctx, char *buffer, int buffer_size) {
    FILE *fp = ctx->client_fp;
    int ret = -1;
    
    while (!interrupted) {
        /* Wait for the start character, '$', ignoring others. */

        while (!interrupted) {
            int ch = log_getc(fp);

            if(interrupted) break;

            if(ch == EOF){
                ret = -1;
                goto leave; 
            }

            if(errno == EWOULDBLOCK || errno == EAGAIN) {
                errno = 0;
#ifdef DEBUG
                printf("log_getc timeout\n");
#endif
                return 0;
            }

            if (ch == '$') {
                break;
            }

            if (ch == '\3') {
                /* Special-case packet : interrupt from client */
                assert(buffer_size >= 2);
                buffer[0] = ch;
                buffer[1] = '\0';
                
                ret = 1;

                goto leave;
            }
#ifdef DEBUG
            fprintf(stderr, "Unexpected char: '%c' (%i)\n", ch, ch);
#endif
        }

        if(interrupted) {
            printf("Interrupted while reading packet\n");
            goto leave;
        }

        int count = 0;
        uint8_t checksum = 0;
        while (1) {
            assert(count < buffer_size);
            char ch = log_getc(fp);
            if (ch == '#')
                break;
            checksum += ch;
            buffer[count++] = ch;
        }
        buffer[count] = 0;
        uint8_t received_checksum = hex_to_int(log_getc(fp)) << 4;
        received_checksum += hex_to_int(log_getc(fp));
        if (received_checksum != checksum) {
            fprintf(stderr, "got bad checksum: 0x%02x != 0x%02x\n",
                    received_checksum, checksum);
            fwrite("-", sizeof(char), 1, fp);
        } else {
        if(!ctx->no_ack_mode)
            fwrite("+", sizeof(char), 1, fp);
        }
        fflush(fp);
        if (received_checksum == checksum) {
#ifdef DEBUG
            fprintf(stderr, "received: '%s'\n", buffer);
#endif
            ret = 1;

            goto leave;
        }
    }
    
leave:
    return ret;
}

void put_packet(vmi_dbg_ctx *ctx, char *packet) {
    FILE *fp = ctx->client_fp;
    fwrite("$", sizeof(char), 1, fp);
    uint8_t checksum = 0;
    char *ptr;
    for (ptr = packet; *ptr != 0; ptr++) {
        assert(*ptr != '$');
        assert(*ptr != '#');
        fwrite(ptr, sizeof(char), 1, fp);
        checksum += *ptr;
    }
    fwrite("#", sizeof(char), 1, fp);
    char hex[2] = {0};
    write_hex_byte((uint8_t*)&hex, checksum);
    fwrite(hex, sizeof(char), 2, fp);
#ifdef DEBUG
    fprintf(stderr, "sent: '%s'\n", packet);
#endif
    fflush(ctx->client_fp);

    /* Look for acknowledgement character. */
    if(!ctx->no_ack_mode){
        char ch = log_getc(fp);
        if (ch != '+') {
            fprintf(stderr, "Unexpected ack char: '%c' (%i)\n", ch, ch);
        }
    }

}

void gdb_step_notify(vmi_instance_t vmi, vmi_event_t *event){

    vmi_dbg_ctx *ctx = NULL;

    if(!event || event->type != VMI_EVENT_SINGLESTEP) {
        fprintf(stderr, "ERROR (%s): invalid event encounted\n", __FUNCTION__);
        return;
    }

    if(!event->data) {
        fprintf(stderr, "ERROR (%s): gdbstub ctx not found in"
                " event.\n", __FUNCTION__);
        return;
    }

    ctx = event->data;

    /* we stepped n-times to get here
     *  need to notify GDB client, await directive (which will be
     *   step again or perhaps continue)
     */
    if(!ctx->vm_paused){
        vmi_pause_vm(ctx->vmi);
        ctx->vm_paused = 1;
    }

printf("gdb step notify, paused. sending stop reply now\n");
    char *pid = NULL;
    asprintf(&pid, "T05thread:p%x.%x;core:%x;", ctx->pid, ctx->tid, event->vcpu_id);
    put_packet(ctx, pid);
    free(pid);

    return;
}

void gdb_bp_notify(vmi_instance_t vmi, vmi_event_t *event){

    vmi_dbg_ctx *ctx = NULL;
    breakpoint_t *bp = NULL;

    if(!event || event->type != VMI_EVENT_INTERRUPT) {
        fprintf(stderr, "ERROR (%s): invalid event encounted\n", __FUNCTION__);
        return;
    }

    if(!event->data) {
        fprintf(stderr, "ERROR (%s): gdbstub ctx not found in"
                " event.\n", __FUNCTION__);
        return;
    }

    ctx = event->data;

    bp = g_hash_table_lookup(ctx->bp_lookup, &event->interrupt_event.gla);

    if(!bp) {
        fprintf(stderr, "ERROR (%s): breakpoint for address='%lx' not found.\n",
                __FUNCTION__, event->interrupt_event.gla);

        /* Assume that it's a breakpoint set from within the guest, so be sure
         *  to reinject to avoid surprises and keep the VM running sanely.
         */
        event->interrupt_event.reinject = 1;

        return;
    }

    /* This is a breakpoint that we set, so as a default, prevent reinjection.
     *  The callback if present may elect to reinject (for GDB, it would be odd to
     *   use a callback here).
     */
    event->interrupt_event.reinject = 0;

#ifdef DEBUG_EXTRA
    printf("Breakpoint='%s' hit @ RIP=0x%lx GFN=0x%lx. VCPU=%u!\n",
        bp->name, event->interrupt_event.gla, event->interrupt_event.gfn, event->vcpu_id);
#endif

    /* pause because we have now STOPPED due to the trap, and are awaiting:
     *  1) a breakpoint removal from GDB client
     *  2) a step packet to perform the original instruction
     *      2a) must unpause there after setting up the singlestep event
     *      2b) must pause in step callback after receiving the singlestep event
     *  3) a re-establishment of the breakpoint after stepping 
     *  4) a continue or subsequent step packet, in which case see step 2
     */
    if(!ctx->vm_paused){
        vmi_pause_vm(ctx->vmi);
        ctx->vm_paused = 1;
    }

    if(bp->callback){
       bp->callback(vmi, bp);
    }

printf("attempting to send bp notification\n");
    char *pid = NULL;
    asprintf(&pid, "T05thread:p%x.%x;core:%x;", ctx->pid, ctx->tid, event->vcpu_id);
    put_packet(ctx, pid);
    free(pid);
printf("successfully sent bp notification\n");

    return;
}

void vmi_regs_to_gdb(vmi_instance_t vmi, struct gdb_regs *regs, unsigned long vcpu, uint32_t word_size){
    memset(regs, 0, sizeof(struct gdb_regs));
    if(word_size == 4){
#ifndef LIBVMI_HAS_32B_REGS
#warning libvmi needs 32bit registers defined
#else
        reg_t val = 0;
        vmi_get_vcpureg(vmi, &val, EAX, vcpu);
        regs->regs32.eax = *((uint32_t*)&val);

        vmi_get_vcpureg(vmi, &val, EBX, vcpu);
        regs->regs32.ebx = *((uint32_t*)&val);
        
        vmi_get_vcpureg(vmi, &val, EAX, vcpu);
        regs->regs32.ecx = *((uint32_t*)&val);

        vmi_get_vcpureg(vmi, &val, EDX, vcpu);
        regs->regs32.edx = *((uint32_t*)&val);
        
        vmi_get_vcpureg(vmi, &val, ESI, vcpu);
        regs->regs32.esi = *((uint32_t*)&val);

        vmi_get_vcpureg(vmi, &val, EDI, vcpu);
        regs->regs32.edi = *((uint32_t*)&val);

        vmi_get_vcpureg(vmi, &val, ESP, vcpu);
        regs->regs32.esp = *((uint32_t*)&val);

        vmi_get_vcpureg(vmi, &val, EBP, vcpu);
        regs->regs32.ebp = *((uint32_t*)&val);

        vmi_get_vcpureg(vmi, &val, EFLAGS, vcpu);
        regs->regs32.eflags = *((uint32_t*)&val);

        vmi_get_vcpureg(vmi, &val, EIP, vcpu);
        regs->regs32.eip = *((uint32_t*)&val);
#endif

    } else {
        vmi_get_vcpureg(vmi, &regs->regs64.rax, RAX, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.rbx, RBX, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.rcx, RCX, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.rdx, RDX, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.rsi, RSI, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.rdi, RDI, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.rbp, RBP, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.rsp, RSP, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.rip, RIP, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.r8, R8, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.r9, R9, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.r10, R10, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.r11, R11, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.r12, R12, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.r13, R13, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.r14, R14, vcpu);
        vmi_get_vcpureg(vmi, &regs->regs64.r15, R15, vcpu);

        reg_t val = 0;
        vmi_get_vcpureg(vmi, &val, RFLAGS, vcpu);
        regs->regs64.eflags = *((uint32_t*)&val);
    }
   
    // common to both. todo 
    // regs->cs regs->ss regs->ds regs->es regs->fs regs->gs;
}

int gdb_rsp_interrupt_sequence(vmi_dbg_ctx *ctx, char * request) {
    printf("interrupt sent by client\n");
    /* By playing with gdb as a client for gdbserver running bash, it seems
     *  that SIGINT (02) is the stop reply packet sent here, which
     *  makes sense even though it doesn't imply an actual SIGINT was delivered
     *  to the process
     */
    
    /* UNCONDITIONAL pause, awaiting input from client
     *  We will only resume on a continue, here.
     */    
    vmi_pause_vm(ctx->vmi);
    ctx->vm_paused = 1;

//quote from gdb manual "If the target supports debugging of multiple threads and/or processes, it should attempt to interrupt all currently- executing threads and processes. If the stub is successful at interrupting the running pro- gram, it should send one of the stop reply packets (see Section E.3 [Stop Reply Packets], page 514) to gdb as a result of successfully stopping the program in all-stop mode, and a stop reply for each stopped thread in non-stop mode. Interrupts received while the program is stopped are discarded."
    if(ctx->non_stop_mode) {
        /* FIXME this needs a loop to report all threads stopped
         *  if attached to a particular pid, we probably need to report just
         *      its threads as stopped
         *  if attached to a kernel thread or to nothing at all, we need to
         *      report all threads stopped across all vcpus
         */
     
        if(ctx->multiprocess_extended){
            printf("interrupt from client in multiprocess extended mode: must stop"
                " all processes\n");
            //FIXME
        }
    } else {
        /* must generate a reply like : T02thread:x;thread:x
         *  where x is a thread id in extended-mode format pPID.TID
         */
        char reply[MAX_VMIDBG_PACKET] = {0};
        char *r = reply;

        addr_t list_head = 0;
        addr_t next_process = 0;
        vmi_pid_t task_pid = -1;

        int pid_offset = vmi_get_offset(ctx->vmi, "linux_pid");
        int tasks_offset = vmi_get_offset(ctx->vmi, "linux_tasks");

        list_head = next_process = vmi_translate_ksym2v(ctx->vmi, "init_task");

        strncat(r, "T02", 3);
        r+=3;

        do {
            vmi_read_32_va(ctx->vmi, next_process + pid_offset, 0, (uint32_t*)&task_pid);

            int written = snprintf(r, MAX_VMIDBG_PACKET-strlen(reply), "thread:p%x.%x;", task_pid, task_pid);
            r+= written;

            vmi_read_addr_va(ctx->vmi, next_process + tasks_offset, 0, &next_process);
            next_process -= tasks_offset;

            /* if we are back at the list head, we are done */
        } while(list_head != next_process);

        put_packet(ctx, reply);
    }
   
    return 0;
}

int gdb_rsp_enable_extended(vmi_dbg_ctx *ctx, char * request) {
    printf("extended multiprocess mode enabled by client\n");
    //FIXME this is supposed to ALSO make the gdbserver persistent
    //  unsure of implications
    ctx->multiprocess_extended = 1;
    put_packet(ctx, "OK");

    return 0;
}

int gdb_rsp_query_status(vmi_dbg_ctx *ctx, char * request) {
/* FIXME normally this packet is only sent at initialization, so if received,
 *        we should clear out any breakpoints we know about in case GDB is
 *        restarting. However, it is also sent during a mode change -- see
 *        section 'E.10 Remote Protocol Support for Non-Stop Mode' in docs.
 *
 *       In addition, we should suspend execution until gdb decides what to do
 *          TODO revisit, to make sure this makes sense. It may be better to
 *          avoid suspending until an interrupt lands.
 *            (this might be satisfied with the ctx->pause_at_init variable)
 */

    /* for now, hardcoding "NO SIGNAL" */
    int signum = 0;
    char reply[MAX_VMIDBG_PACKET] = {0};


    if(ctx->pause_at_init){
        vmi_pause_vm(ctx->vmi);
        ctx->vm_paused = 1;
    }

    snprintf(reply, sizeof(reply), "S%02x", signum);
    put_packet(ctx, reply);

    return 0;
}

int gdb_rsp_read_reg_single(vmi_dbg_ctx *ctx, char * request) {
    printf("Write specific register attempt\n");
    //todo fixme
    put_packet(ctx, "");

    return 0;
}

int gdb_rsp_write_reg_single(vmi_dbg_ctx *ctx, char * request){
    // TODO FIXME IMPLEMENT
    printf("write register attempt\n");
    put_packet(ctx, "");

    return 0;
}

int gdb_rsp_read_reg_all(vmi_dbg_ctx *ctx, char * request) {

    char reply[MAX_VMIDBG_PACKET] = {0};
    struct gdb_regs regs;
    uint32_t word_size = vmi_get_address_width(ctx->vmi);
    //FIXME TODO vcpu id needed
    //  need to use context of process or kernel thread
    //  OR if gdb knows to indicate thread in packet, use what it requests
    //
    //  VCPU ID set to 0 hardcoded for now
    vmi_regs_to_gdb(ctx->vmi, &regs, 0, word_size);

    if(word_size == 4){
        write_hex_bytes(reply, (uint8_t*)&regs.regs32, sizeof(regs.regs32));
        reply[sizeof(regs.regs32) * 2] = 0;
    } else {
        write_hex_bytes(reply, (uint8_t*)&regs.regs64, sizeof(regs.regs64));
        reply[sizeof(regs.regs64) * 2] = 0;
    }
    put_packet(ctx, reply);

    return 0;
}

int gdb_rsp_write_reg_all(vmi_dbg_ctx *ctx, char * request) {

    printf("write registers all attempt\n");
    /* TODO */
    put_packet(ctx, "");

    return 0;
}

int gdb_rsp_read_mem(vmi_dbg_ctx *ctx, char * request) {
    char *rest = NULL;
    addr_t mem_addr = strtoull(request + 1, &rest, 16);
    assert(*rest == ',');
    size_t mem_size = strtoll(rest + 1, &rest, 16);
    assert(*rest == 0);
    char reply[MAX_VMIDBG_PACKET] = {0};
    uint8_t * vmibuf = calloc(1, mem_size);
    vmi_read_va(ctx->vmi, mem_addr, 0, vmibuf, mem_size);
    write_hex_bytes(reply, vmibuf, mem_size);
    free(vmibuf);
    reply[mem_size * 2] = 0;
    put_packet(ctx, reply);

    return 0;
}

int gdb_rsp_write_mem(vmi_dbg_ctx *ctx, char * request) {

    printf("write mem attempt\n");
    /* TODO */
    put_packet(ctx, "");

    return 0;
}

int gdb_rsp_write_mem_binary(vmi_dbg_ctx *ctx, char * request) {

    printf("write mem attempt (binary)\n");
    /* TODO */
    put_packet(ctx, "");

    return 0;
}
int gdb_rsp_get_query(vmi_dbg_ctx *ctx, char * request) {

    if (strncmp(request, "qAttached", 9) == 0){
        /* always reply that we are already attached to a program.
         *  This "should" cause GDB to detach on quit, rather than kill.
         */
        put_packet(ctx, "1");
    } else if(strncmp(request, "qC", 2) == 0){
        /* query thread id */

#if 0
        if(ctx->multiprocess_extended){
            /* always start using PID 1 here. Even if it's bogus, gdb doesn't like pid 0. Alternatitive = pid of first located kernel thread? */
            put_packet(ctx, "QCp01.01");
            //TODO FIXME, report ctx->pid
        } else {
            put_packet(ctx, "QC-1");
        }
#endif

        /* 
            qC. An empty reply is used, which is interpreted as "use the previously selected thread". 
            Since no thread is ever explicitly selected by the target, this will allow the client GDB
            session to use its default NULL thread, which is what is wanted.
        */
#ifdef DEBUG
        printf("handling qC with an empty response, meaning 'use previous thread or default'\n");
#endif
        put_packet(ctx, "");
    } else if(strncmp(request, "qSupported", 10) == 0){
        char *supported_str = NULL;
        asprintf(&supported_str,
            //"PacketSize=%x;multiprocess+;QStartNoAckMode+;qXfer:features:read+",
            "PacketSize=%x;multiprocess+;ConditionalBreakpoints+;QStartNoAckMode+;qXfer:features:read+",
            MAX_VMIDBG_PACKET-1);
        put_packet(ctx, supported_str);
        free(supported_str);

    } else if(strncmp(request, "qXfer:", 6) == 0){
        if(strstr(request+6, "features:read")){
            if(vmi_get_address_width(ctx->vmi) == 4){
                put_packet(ctx, "l"I386_TARGET);
            } else if(vmi_get_address_width(ctx->vmi) == 8){
              put_packet(ctx, "l"X86_64_TARGET);
            } else {
                fprintf(stderr, "ERROR: unknown vm arch\n");
                put_packet(ctx, "");
            }
        } else {
            fprintf(stderr, "ERROR: Unknown qXfer packet'\n");
            put_packet(ctx, "");
        }
    } else if (strncmp(request, "qRcmd,", 6) == 0){
        int len = strlen(request+6);

        /* we expect an even number of ASCII values encoded as a hex string */
        if ( (len % 2) != 0 ) {
            /* if not even #, fail */
            printf("q packet cmd, invalid len, request='%s'\n", request);
            put_packet(ctx, "E01");
            goto bail;
        }
      
        len = len / 2;
        char * cmd = calloc(1, len+1);

        hex_to_mem((uint8_t*)cmd, request + 6, len); 
        printf("COMMAND: %s\n", cmd);

        /* do stuff here, process cmd */
        char * response_txt = NULL;
        if ( strncmp(cmd, "show vm", 7) == 0 ){
            char *vm_name = vmi_get_name(ctx->vmi);
            asprintf(&response_txt,
                "vm_name='%s' domid='%lu' addr_width='%u'"
                " os_type='%u' page_mode='%u'\n",
                vm_name, vmi_get_vmid(ctx->vmi), vmi_get_address_width(ctx->vmi),
                vmi_get_ostype(ctx->vmi), vmi_get_page_mode(ctx->vmi));
            free(vm_name);
        } else {
            response_txt = strdup("awesome cmd response\n");
        }
        
        free(cmd);

        size_t resp_len = strlen(response_txt);
        char * response_hex = calloc(1, resp_len*2+1);
      
        write_hex_bytes(response_hex, (uint8_t*)response_txt, resp_len);
        free(response_txt);

        put_packet(ctx, response_hex);
    } else if (strncmp(request, "qTfV", 4) == 0 || strncmp(request, "qTsV", 4) == 0){
        /*
         * qTfV == "first" query about trace variables
         * qTsV == "subsequent" queries about trace variables if first was not enough
         */
#ifdef DEBUG
        printf("q tracepoint variable check\n");
#endif
        put_packet(ctx, "");
    } else if (strncmp(request, "qTfP", 4) == 0 || strncmp(request, "qTsP", 4) == 0){
        /*
         * qTfP == "first" query about tracepoints
         * qTsP == "subsequent" queries about tracepoints if first was not enough
         */
#ifdef DEBUG
        printf("q tracepoint something or other\n");
#endif
        put_packet(ctx, "");
    } else if (strncmp(request, "qTStatus", 8) == 0){
#ifdef DEBUG
        printf("q tracepoint status check\n");
#endif
        //observed response: T0;tnotrun:0;tframes:0;tcreated:0;tfree:500000;tsize:500000;circular:0;disconn:0;starttime:000000000;stoptime:000000000;username::;notes::
        put_packet(ctx, "T0;tnotrun:0;tframes:0;tcreated:0;tfree:500000;tsize:500000;circular:0;disconn:0;starttime:000000000;stoptime:000000000;username::;notes::");
    } else {
#ifdef DEBUG
        printf("unhandled q packet received: %s\n", request);
#endif
        put_packet(ctx, "");
    }

    return 0;

bail:
    return 1;
}

int gdb_rsp_set_query(vmi_dbg_ctx *ctx, char * request) {

    if(strncmp(request, "QStartNoAckMode", 15) == 0){
        printf("Enabling no-ack mode\n");
        ctx->no_ack_mode = 1;
        put_packet(ctx, "OK");
    } else {
        printf("unhandled set query attempt packet='%s'\n", request);
        put_packet(ctx, "");
    }

    return 0;
}

int gdb_rsp_set_thread(vmi_dbg_ctx *ctx, char * request) {

    /* 0.0 means 'arbitrary thread or process';
     *      INTERPRET as libvmi operations targeting the
     *          kernel not any process OR "the last thread active" ?
     * -1 means 'all processess or threads'\n");
     *      INTERPRET as libvmi operations targeting the kernel not any process
     */

    char *rest = NULL;
    char * set_thread_request = request+1;
    
    //HcpPID.TID
    unsigned long pid = strtoul(set_thread_request+3, &rest, 16);
    unsigned long tid = 0; 
    if(rest && *rest == '.') tid = strtoul(rest+1, NULL, 16);

#ifdef DEBUG
    printf("set thread context for subsequent operations (read/write mem, read/write registers, step/continue, etc)\n");
    printf("pid.tid for request '%s' is %lu.%lu\n", request, pid, tid);
#endif

    ctx->pid = pid;
    ctx->tid = tid;

    switch(set_thread_request[0]){
    case 'g':
#ifdef DEBUG
        printf("set thread_context for reg read\n");
#endif
        put_packet(ctx, "OK");
        break;
    case 'c':
#ifdef DEBUG
        printf("set thread_context for step/continue\n");
#endif
        put_packet(ctx, "OK");

        break;
    default:
#ifdef DEBUG
        printf("unhandled set thread_context attempt\n");
#endif
        put_packet(ctx, "E01");
        break;
    }

    return 0;
}

int gdb_rsp_detach_proc(vmi_dbg_ctx *ctx, char * request) {

    if(strncmp(request, "D;", 2) == 0){
        uint32_t thepid = strtoul(request + 2, NULL, 16);
        printf("Attempting to detach from PID=%u\n", thepid);
        put_packet(ctx, "OK");
    } else if (strncmp(request, "D", 1) == 0) {
        printf("Attempting to detach in general\n");
        put_packet(ctx, "OK");
    } else {
        fprintf(stderr, "ERROR: Unknown detach packet'\n");
        put_packet(ctx, "");
    }

    return 0;
}

/* Handle continue operations for old-style plain 'c' packets only
 *  For vCont style continue packets, see gdb_rsp_vcontinue
 *
 * NOTE: response packet is deferred until later when a stop actually
 *       occurs
 */
int gdb_rsp_continue(vmi_dbg_ctx *ctx, char *request){
    int ret = 0;

    /* FIXME use isVcont */

    /* handle a request to continue at a particular address */
    if(request[1] != '\0'){
        //plain continue
        ret = 0;
        goto finish;
    }

    if (request[1] == ':'){
        /* this is a vCont style continue: unpack thread ID */
    } 

    //this is a plain continue with an address specification
        //this should be an address, convert.
        //TODO unpack address 
        //TODO set RIP to address

    if(ctx->vcpus_paused){
        /* FIXME: here we need to unpause specific VCPUs which may be suspended
         *        while other separate VCPUs are still running.
         */
    }

    if(ctx->vm_paused){
        ctx->vm_paused = 0;
        vmi_resume_vm(ctx->vmi);
    }

finish:
    return ret;
}

/* Handle continue operations for vCont 'c' packets only
 *  For plain 'c' style continue packets, see gdb_rsp_continue
 *
 * NOTE: response packet is deferred until later when a stop actually
 *       occurs
 */
int gdb_rsp_vcontinue(vmi_dbg_ctx *ctx, char *request){
    int ret = 0;

    /* Excerpt from gdb docs:
     * "Resume the inferior, specifying different actions for each thread. If
     *  an action is specified with no thread-id, then it is applied to any
     *  threads that don't have a specific action specified; if no
     *  default action is specified then other threads should remain stopped
     *  in all-stop mode and in their current state in non-stop mode.
     *  Specifying multiple default actions is an error; specifying no actions
     *  is also an error. Thread IDs.."  are specifed using 'pPID.TID' format
     *  common in multiprocessing mode
     */

    /* 'Default action' vCont continue:
     *   if set, applies a continue to all threads that lack a
     *   specific directive
     */
    int has_default_c = !!strstr(request, "c;");

    if(has_default_c){
        /* needs something like
        GSList * touched_threads = NULL;
        GSList * all_threads = ctx->kernel_perspective ? 
            get_all_processes(ctx) :
            get_all_process_threads(ctx);
        */
    }

    /* NOTE: vCont c and s packets do not support the optional 'address' argument */
    if(request[1] != '\0'){
        ret = 0;
        goto finish;
    }

    if(ctx->vcpus_paused){
        /* FIXME: here we need to unpause specific VCPUs which may be suspended
         *        while other separate VCPUs are still running.
         */
    }

    if(ctx->vm_paused){
        ctx->vm_paused = 0;
        vmi_resume_vm(ctx->vmi);
    }

    char *this_action = strstr(request, ";");

    if(!this_action){
        fprintf(stderr, "vCont bad packet : '%s'\n", request);
        goto err_packet;
    }

    do {
        /* step past ; */
        this_action++;
     
        /* below, we pass forward the full request because of the semantics
         *  of 'default' and 'specified' actions: the former applies
         *  to all active threads NOT enumerated by specified actions,
         *  so the whole request needs to be parsed
         */
        switch(this_action[0]){
        case 'c': /* continue process/thread(s) */
            gdb_rsp_vcontinue(ctx, request);
            break;

        case 's': /* step process/thread(s) */
            /* FIXME !! vCont doesn't work because c and s here don't call continue/step. make sure to do that!
            gdb_rsp_vsinglestep(ctx, request);
            */
            break;
        case 't': /* stop process and thread */
            /* FIXME be sure to handle vCont;t */
            /* still not really sure what this is */
            break;
        default:
            fprintf(stderr, "vCont unhandled action '%c' : '%s'\n", this_action[0], request);
            goto err_packet;
            break;
        }

    } while ((this_action = strstr(this_action, ";")) && *this_action != '\0');

finish:
    return ret;

err_packet:
    put_packet(ctx, "E01");
    return 1;
}



int gdb_rsp_singlestep(vmi_dbg_ctx *ctx, char *request){
    /* step once to perform the original instruction and then replace the breakpoint */
//TODO FIXME somehow infer the event vcpud,
    vmi_event_t *event = calloc(1, sizeof(vmi_event_t));
    event->type = VMI_EVENT_SINGLESTEP;
    event->vcpu_id = 0;
    event->data = ctx;

    vmi_step_event(ctx->vmi, event, event->vcpu_id, 1, gdb_step_notify);

    /* we should really only land here if we're paused, so
     *  unconditionally unpause so that the just-established
     *  singlestep can proceed
     */
    vmi_resume_vm(ctx->vmi);
    ctx->vm_paused = 0;

    printf("singlestep attempt\n");
    //TODO implement
    put_packet(ctx, "OK");
    return 0;
}

int gdb_rsp_breakpoint(vmi_dbg_ctx *ctx, char *request){

    printf("process breakpoint\n");

    int insert = request[0] == 'Z';
    char *rest = NULL;
    long kind = 0;
    addr_t mem_addr = 0;

    switch(request[1]){
    case '0': /* software INT3 breakpoint */
        mem_addr = strtoull(request + 3, &rest, 16);
        assert(*rest == ',');
        kind = strtol(rest + 1, &rest, 16);
        assert(*rest == 0);

        if(insert){

            printf("insert bp at %lx of size %ld\n", mem_addr, kind); 

            breakpoint_t * new_bp = calloc(1, sizeof(breakpoint_t));

            new_bp->address = mem_addr; 
            new_bp->name = strdup("gdb_bp");

            /* FIXME - use "current thread" context set by previous packets */
            new_bp->pid = 0; /* hard-coded to 0 for testing */
            new_bp->callback = NULL;
            new_bp->event = ctx->int3_event;
            new_bp->discard = FALSE;
            new_bp->ctx = ctx;

            /* save a reference */
            g_hash_table_insert(ctx->bp_lookup, &(new_bp->address), new_bp);

            /* 1) save 'real' instruction and install int3. No real need to pause yet */
            vmi_read_8_va(ctx->vmi, new_bp->address, new_bp->pid, &new_bp->backup_byte);

            /* 2) pause for sanity/safety */
            //if(!ctx->vm_paused) vmi_pause_vm(ctx->vmi);

            /* 3) install the breakpoint */
            vmi_write_8_va(ctx->vmi, new_bp->address, new_bp->pid, &INT3_INSTR);

            //if(!ctx->vm_paused) vmi_resume_vm(ctx->vmi);
        } else {
            /* remove */
            printf("remove bp at %lx of size %ld\n", mem_addr, kind); 
            breakpoint_t *bp = g_hash_table_lookup(ctx->bp_lookup, &mem_addr);
            if(bp){
                if(!ctx->vm_paused) vmi_pause_vm(ctx->vmi);
                vmi_write_8_va(ctx->vmi, bp->address, bp->pid, &bp->backup_byte);
                if(!ctx->vm_paused) vmi_resume_vm(ctx->vmi);
            } else {
                fprintf(stderr, "GDB BP at address %lx not found\n", mem_addr);
            }
        }
        put_packet(ctx, "OK");
        break;

    case '1': /* hardware debug-register breakpoint */
        /* TODO, someday, when Xen provides DR mem events */
        fprintf(stderr, "Unhandled z1/Z1 packet'\n");
        break;

    case '2': /* write watchpoint */
        /* TODO implement using a mem_event W */
        fprintf(stderr, "Unhandled z2/Z2 packet'\n");
        put_packet(ctx, "");
        break;

    case '3': /* read watchpoint */
        /* TODO implement using a mem_event RX */
        fprintf(stderr, "Unhandled z3/Z3 packet'\n");
        put_packet(ctx, "");
        break;

    case '4': /* access watchpoint (read or write) */
        /* TODO implement using a mem_event RW */
        fprintf(stderr, "Unhandled z4/Z4 packet'\n");
        put_packet(ctx, "");
        break;
    default:
        fprintf(stderr, "Unhandled z packet'\n");
        break;
    }

    return 0;
}

int gdb_rsp_process_extended(vmi_dbg_ctx *ctx, char *request){
    
    if(strncmp(request, "vKill;", 6) == 0){
        fprintf(stderr, "vKill packet'\n");
        put_packet(ctx, "OK");
    } else if(strncmp(request, "vCont", 5) == 0){
        char *vCont_request = request + 5;
        /* handle 'vCont?' packet */
        if ( vCont_request[0] == '?'){
            /* return semi-colon separated list of supported vCont operations
             *  which are single character: c, C, s, S, t
             *
             *  Report c, s, t as supported
             *
             *  TODO verify above that C and S can't be supported.
             */
        
            put_packet(ctx, "vCont;c;s;t");
            /* NOTE TODO : 
             *
             * when advertised as above, the gdb client
             *  doesnt believe vCont is supported.
             *
             * when advertised as below, it does believe it
             *
             * HOWEVER: breakpoints work with the above, not the below
             */
            //put_packet(ctx, "vCont;c;C;S;s;t");

            return 0;
        }

        /* format: vCont[;action[:thread-id]]... 
         *  different actions for each specified thread;
         */

        char *this_action = strstr(request, ";");

        if(!this_action){
            fprintf(stderr, "vCont bad packet : '%s'\n", request);
            goto err_packet;
        }

        do {
            /* step past ; */
            this_action++;
         
            /* below, we pass forward the full request because of the semantics
             *  of 'default' and 'specified' actions: the former applies
             *  to all active threads NOT enumerated by specified actions,
             *  so the whole request needs to be parsed
             */
            switch(this_action[0]){
            case 'c': /* continue process/thread(s) */
                gdb_rsp_vcontinue(ctx, request);
                break;

            case 's': /* step process/thread(s) */
                /* FIXME - vCont doesn't work because c and s here don't call continue/step. make sure to do that!
                 * gdb_rsp_vsinglestep(ctx, request);
                 */
                break;
            case 't': /* stop process and thread */
                /* FIXME vCont;t */
                /* still not really sure what this is */
                break;
            default:
                fprintf(stderr, "vCont unhandled action '%c' : '%s'\n", this_action[0], request);
                goto err_packet;
                break;
            }

        } while ((this_action = strstr(this_action, ";")) && *this_action != '\0');

        if(ctx->vm_paused){
            vmi_resume_vm(ctx->vmi);
            ctx->vm_paused = 0;
        }
    } else if(strncmp(request, "vAttach;", 8) == 0){
        /* "lock" to keep things quiesced-ish to verify that
         *  the requested PID is present
         */
        if(!ctx->vm_paused) vmi_pause_vm(ctx->vmi);

        /* TODO 1) extract requested pid
                2) examine kernel list to be sure it's there
                3) record pgd, pid, etc as "currently debugged task"
                3) if there, say OK or send stop packet. else, reply with error and return
         */

        if(ctx->non_stop_mode) {
            //TODO FIXME decide whether to pause vm or something here
            put_packet(ctx, "OK");
        } else {
            /* an appropriate stop signal */
            //TODO FIXME decide whether to pause vm or something here
            //see gdb-src/include/gdb/signals.def for integer definitions
            // S00 == no signal
            // S01 == SIGHUP
            // S02 == SIGINT
            // s03 == SIGQUIT
            // S04 == SIGILL
            // S05 == sigtrap
            // S09 == SIGKILL
            // S11 == SIGSEGV
            // S15 == SIGTERM
            // S13 == SIGPIPE
            put_packet(ctx, "S00");
        }
        
        /* "unlock" and keep going */
        if(!ctx->vm_paused) vmi_resume_vm(ctx->vmi);
    } else {
        fprintf(stderr, "ERROR: unhandled extended v packet'\n");
        put_packet(ctx, "");
    }

    return 0;

err_packet:
    put_packet(ctx, "E01");
    return 1;
}

void handle_windbg(vmi_dbg_ctx *ctx){
#if 0
    while (!interrupted) {
        status_t s = vmi_events_listen(ctx->vmi,100);
        if(s != VMI_SUCCESS){
            fprintf(stderr, "Error listening for events, must now exit\n");
            interrupted = 1;
            break;
        }

        char request[MAX_VMIDBG_PACKET] = {0};
        int rc = get_gdb_packet(ctx, request, sizeof(request));

        if (rc == 0) {
            /* timed out while attempting to read packet;
             *  buffer has no content.
             */
printf("handle windbg noticed get_gdb_packet timeout\n");
            continue;
        }

        if ( rc == -1 ){
            fprintf(stderr, "Error encountered while reading packet\n");
            break;
        }

        switch (request[0]) {
        case '\3': /* ctrl-C or other interrupt from client */
            gdb_rsp_interrupt_sequence(ctx, request);
            break;

        case '!': /* extended mode enabled */
            gdb_rsp_enable_extended(ctx, request);
            break;

        case '?': /* query stopped status */
            gdb_rsp_query_status(ctx, request);
            break;

        case 'p': /* read SPECIFIC register */
            gdb_rsp_read_reg_single(ctx, request);
            break;
        case 'P': /* older write registers */
            gdb_rsp_write_reg_single(ctx, request);
            break;

        case 'g': /* read registers */
            gdb_rsp_read_reg_all(ctx, request);
            break;
        case 'G': /* write registers */
            gdb_rsp_write_reg_all(ctx, request);
            break;

        case 'H': /* set thread context */
            gdb_rsp_set_thread(ctx, request);
            break;


        case 'M': /* write memory */
            gdb_rsp_write_mem(ctx, request);
            break;
        case 'm': /* read memory */
            gdb_rsp_read_mem(ctx, request);
            break;
        case 'X': /* write memory (binary) */
            //gdb_rsp_write_mem_binary(ctx, request);
            break;

        case 'Q': /* query 'set' packet */
            gdb_rsp_set_query(ctx, request);
            break;
        case 'q': /* query 'get' packet */
            gdb_rsp_get_query(ctx, request);
            break;

        case 'Z':
        case 'z':
            gdb_rsp_breakpoint(ctx, request);
            break;

        case 'v': /* extended mode (multiprocess) packets */
            gdb_rsp_process_extended(ctx, request);
            break;
        case 'D': /* detach */
            gdb_rsp_detach_proc(ctx, request);
            break;

        case 'c': /* continue */
            gdb_rsp_continue(ctx, request);
            break;
        case 's': /* single step */
            gdb_rsp_singlestep(ctx, request);
            break;

        case 'B': /* ignored per documentation */
        case 'b': /* ignored per documentation */
        case 'R': /* The 'Restart' command
                   *    ignored for now (TODO 
                   *   Could treat like a reboot, because we can't relaunch a
                   *    task very cleanly.
                   */
        default:
            fprintf(stderr, "ERROR: unhandled packet='%s'\n", request);
            put_packet(ctx, "");
            break;
        }
    }

leave:
    fprintf(stderr, "Aborted\n");
    return;
#endif
}


void handle_gdb(vmi_dbg_ctx *ctx){
    while (!interrupted) {
        status_t s = vmi_events_listen(ctx->vmi,100);
        if(s != VMI_SUCCESS){
            fprintf(stderr, "Error listening for events, must now exit\n");
            interrupted = 1;
            break;
        }

        char request[MAX_VMIDBG_PACKET] = {0};
        int rc = get_gdb_packet(ctx, request, sizeof(request));

        if (rc == 0) {
            /* timed out while attempting to read packet;
             *  buffer has no content.
             */
#if DEBUG
            printf("handlegdb noticed get_gdb_packet timeout\n");
#endif
            continue;
        }

        if ( interrupted ) {
            printf("%s: interrupted, exiting processing loop\n", __FUNCTION__);
            break;
        }

        if ( rc == -1 ){
            fprintf(stderr, "%s: Client disconnected or error encountered while reading packet.\n", __FUNCTION__);
            break;
        }

        switch (request[0]) {
        case '\3': /* ctrl-C or other interrupt from client */
            gdb_rsp_interrupt_sequence(ctx, request);
            break;

        case '!': /* extended mode enabled */
            gdb_rsp_enable_extended(ctx, request);
            break;

        case '?': /* query stopped status */
            gdb_rsp_query_status(ctx, request);
            break;

        case 'p': /* read SPECIFIC register */
            gdb_rsp_read_reg_single(ctx, request);
            break;
        case 'P': /* older write registers */
            gdb_rsp_write_reg_single(ctx, request);
            break;

        case 'g': /* read registers */
            gdb_rsp_read_reg_all(ctx, request);
            break;
        case 'G': /* write registers */
            gdb_rsp_write_reg_all(ctx, request);
            break;

        case 'H': /* set thread context */
            gdb_rsp_set_thread(ctx, request);
            break;


        case 'M': /* write memory */
            gdb_rsp_write_mem(ctx, request);
            break;
        case 'm': /* read memory */
            gdb_rsp_read_mem(ctx, request);
            break;
        case 'X': /* write memory (binary) */
            //gdb_rsp_write_mem_binary(ctx, request);
            break;

        case 'Q': /* query 'set' packet */
            gdb_rsp_set_query(ctx, request);
            break;
        case 'q': /* query 'get' packet */
            gdb_rsp_get_query(ctx, request);
            break;

        case 'Z':
        case 'z':
            gdb_rsp_breakpoint(ctx, request);
            break;

        case 'v': /* extended mode (multiprocess) packets */
            gdb_rsp_process_extended(ctx, request);
            break;
        case 'D': /* detach */
            gdb_rsp_detach_proc(ctx, request);
            break;

        case 'c': /* continue */
            gdb_rsp_continue(ctx, request);
            break;
        case 's': /* single step */
            gdb_rsp_singlestep(ctx, request);
            break;

        case 'B': /* ignored per documentation */
        case 'b': /* ignored per documentation */
        case 'R': /* The 'Restart' command
                   *    ignored for now (TODO 
                   *   Could treat like a reboot, because we can't relaunch a
                   *    task very cleanly.
                   */
        default:
            fprintf(stderr, "ERROR: unhandled packet='%s'\n", request);
            put_packet(ctx, "");
            break;
        }
    }

    fprintf(stderr, "%s complete\n", __FUNCTION__);
    return;
}

int main (int argc, char **argv) {
    vmi_instance_t vmi = NULL;
    server_modes server_mode = INVALID_STUB;

    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);

    int rc = sigaction(SIGHUP,  &act, NULL);
    assert(rc == 0);

    rc = sigaction(SIGTERM, &act, NULL);
    assert(rc == 0);

    rc = sigaction(SIGINT,  &act, NULL);
    assert(rc == 0);

    rc = sigaction(SIGALRM, &act, NULL);
    assert(rc == 0);

    char *name = NULL;

    if(argc < 2){
        fprintf(stderr, "Usage: vmidbg <name of VM>\n");
        exit(1);
    }

    // Arg 1 is the VM name.
    name = argv[1];

    if(argc == 3){
        if(argv[2] && strncasecmp(argv[2], "GDB", 3)){
            server_mode = GDB_STUB;
        } else if(argv[2] && strncasecmp(argv[2], "WINDBG", 3)){
            server_mode = WINDBG_STUB;
        } else {
            fprintf(stderr, "Unspecified server mode, exiting.\n");
            goto fail;
        }
    } else {
        /* if unspecified, assume gdb stub mode */
        server_mode = GDB_STUB;
    }

    // Initialize the libvmi library.
    if (vmi_init(&vmi, VMI_XEN | VMI_INIT_PARTIAL | VMI_INIT_EVENTS, name) == VMI_FAILURE){
        fprintf(stderr, "Failed to init LibVMI library.\n");
        goto fail;
    }

    printf("LibVMI init succeeded!\n");

    vmi_dbg_ctx * ctx = calloc(1, sizeof(vmi_dbg_ctx));
    ctx->vmi = vmi;

    ctx->bp_lookup = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                NULL, (GDestroyNotify)breakpoint_free);
    /* FIXME TODO 
      address not unique enough. maybe PID and address with a custom hashing function? 
        or build a (wastefully large) string out of the same and just use g_str_hash?
      BUT neither will permit a lookup when we really only have an address, without the rest..
      GHashTable *bp_lookup = g_hash_table_new_full(g_str_hash, g_str_equal, free, breakpoint_free);
     */

    vmi_event_t *int3_event = calloc(1, sizeof(vmi_event_t));
    int3_event->type = VMI_EVENT_INTERRUPT;
    int3_event->interrupt_event.reinject = 0;
    int3_event->interrupt_event.intr = INT3;
    int3_event->callback = gdb_bp_notify;
    int3_event->data = ctx;

    ctx->int3_event = int3_event;

    vmi_register_event(vmi, int3_event);

    if(get_connection(ctx) < 0){
        fprintf(stderr, "vmidbg init failed.\n");
        goto fail;
    }

    if(server_mode == GDB_STUB) {
        if(await_client(ctx) < 0){
            fprintf(stderr, "vmidbg new gdb client init failed.\n");
            goto fail;
        }
        printf("Awaiting connection from gdb\n");

        handle_gdb(ctx);

    } else if (server_mode == WINDBG_STUB){
        if(await_client(ctx) < 0){
            fprintf(stderr, "vmidbg new windbg client init failed.\n");
            goto fail;
        }
        printf("Awaiting connection from windbg\n");

        handle_windbg(ctx);

    } else {
        fprintf(stderr, "vmidbg unknown server mode.\n");
        goto fail;
    }

    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    return 0;

fail:
    if(vmi) vmi_destroy(vmi);
    return 1;
}
