/* SPDX-License-Identifier: GPL-3.0-or-later
 * Neutral transport error classes. SMB codes must keep the exact meaning the
 * resident gave them before the mapping existed. */
#define _DEFAULT_SOURCE 1
#include "streamreader/bw_tp_error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define C(x) do { checks++;if(!(x)){fprintf(stderr,"tp_error failure line %d: %s\n",__LINE__,#x);exit(1);} } while(0)

int main(void){
    static const struct {uint32_t nt;enum bw_tp_error error;} nt[]={
        {0,BW_TP_OK},{0xc0000034u,BW_TP_MISSING},{0xc000003au,BW_TP_MISSING},{0xc0000022u,BW_TP_DENIED},
        {0xc0000043u,BW_TP_UNAVAILABLE},{0xc0000103u,BW_TP_UNAVAILABLE},{0xc00000bau,BW_TP_UNAVAILABLE},
        {0xc00000ccu,BW_TP_ROOT_MISSING},{0xc000006du,BW_TP_AUTH},{0xc000006au,BW_TP_AUTH},{0xc0000064u,BW_TP_AUTH},
        /* Codes the resident never recovered from stay fatal. */
        {0x80000006u,BW_TP_TRANSPORT},{0xc000000du,BW_TP_TRANSPORT},{0xc0000035u,BW_TP_TRANSPORT},
        {0xc0000033u,BW_TP_TRANSPORT},{0xc00000b5u,BW_TP_TRANSPORT},{0xffffffffu,BW_TP_TRANSPORT}};
    for(size_t i=0;i<sizeof nt/sizeof *nt;i++)C(bw_tp_error_from_nt(nt[i].nt)==nt[i].error);
    static const struct {int result,mounting;enum bw_tp_error error;} nfs[]={
        {0,0,BW_TP_OK},{17,0,BW_TP_OK},{-ENOENT,0,BW_TP_MISSING},{-ENOENT,1,BW_TP_ROOT_MISSING},
        {-EACCES,0,BW_TP_DENIED},{-EPERM,0,BW_TP_DENIED},{-EACCES,1,BW_TP_AUTH},{-EPERM,1,BW_TP_AUTH},
        {-ENOTDIR,0,BW_TP_UNAVAILABLE},{-EISDIR,0,BW_TP_UNAVAILABLE},{-ESTALE,0,BW_TP_CHANGED},
        {-ELOOP,0,BW_TP_LINKED_OR_SPECIAL},{-EFBIG,0,BW_TP_TOO_LARGE},
        /* Measured on the console: a libnfs RPC timeout surfaces as -EINTR. */
        {-EINTR,0,BW_TP_TIMEOUT},{-EINTR,1,BW_TP_TIMEOUT},{-ETIMEDOUT,0,BW_TP_TIMEOUT},
        {-EIO,0,BW_TP_TRANSPORT},{-ECONNRESET,1,BW_TP_TRANSPORT},{-ENOMEM,0,BW_TP_TRANSPORT}};
    for(size_t i=0;i<sizeof nfs/sizeof *nfs;i++)C(bw_tp_error_from_nfs(nfs[i].result,nfs[i].mounting)==nfs[i].error);
    static const char *const names[]={"ok","missing","denied","unavailable","changed","linked_or_special",
        "too_large","root_missing","auth","timeout","canceled","protocol","transport"};
    C(sizeof names/sizeof *names==BW_TP_ERROR_COUNT);
    for(unsigned i=0;i<BW_TP_ERROR_COUNT;i++)C(!strcmp(bw_tp_error_name((enum bw_tp_error)i),names[i]));
    C(!strcmp(bw_tp_error_name(BW_TP_ERROR_COUNT),"unknown"));C(!strcmp(bw_tp_error_name((enum bw_tp_error)-1),"unknown"));
    printf("{\"tp_error\":%u}\n",checks);
    return 0;
}
