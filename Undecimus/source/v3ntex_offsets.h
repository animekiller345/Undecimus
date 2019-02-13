//
//  v3ntex_offsets.h
//  Undecimus
//
//  Created by Cryptic on 2/12/19.
//  Copyright © 2019 Pwn20wnd. All rights reserved.
//

#ifndef v3ntex_offsets_h
#define v3ntex_offsets_h

#include <common.h>
#include <stdint.h>

typedef struct {
    kptr_t offset_zone_map;
    kptr_t offset_kernel_map;
    kptr_t offset_kernel_task;
    kptr_t offset_realhost;
    kptr_t offset_bzero;
    kptr_t offset_bcopy;
    kptr_t offset_copyin;
    kptr_t offset_copyout;
    kptr_t offset_ipc_port_alloc_special;
    kptr_t offset_ipc_kobject_set;
    kptr_t offset_ipc_port_make_send;
    kptr_t offset_rop_ldr_r0_r0_0xc;
    kptr_t offset_chgproccnt;
    kptr_t offset_kauth_cred_ref;
    kptr_t offset_OSSerializer_serialize;
} v3ntex_offsets;

#ifdef __cplusplus
extern "C"
#endif
v3ntex_offsets*
get_v3ntex_offsets(const char* filename);

#endif /* v3ntex_offsets_h */
