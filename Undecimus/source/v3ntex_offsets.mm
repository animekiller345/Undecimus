//
//  v3ntex_offsets.mm
//  Undecimus
//
//  Created by Cryptic on 2/12/19.
//  Copyright © 2019 Pwn20wnd. All rights reserved.
//

#include "v3ntex_offsets.h"
#include <liboffsetfinder64/liboffsetfinder64.hpp>

static v3ntex_offsets v3ntex_offs;

extern "C" v3ntex_offsets* get_v3ntex_offsets(const char* filename)
{
    LOG("Initializing offsetfinder64...");
    tihmstar::offsetfinder64 fi(filename);
    LOG("Successfully initialized offsetfinder64.");
    LOG("Finding offsets for v3ntex with liboffsetfinder64...");
    try {
        v3ntex_offs.offset_zone_map = (kptr_t)fi.find_zone_map();
        v3ntex_offs.offset_kernel_map = (kptr_t)fi.find_kernel_map();
        v3ntex_offs.offset_kernel_task = (kptr_t)fi.find_kernel_task();
        v3ntex_offs.offset_realhost = (kptr_t)fi.find_realhost();
        v3ntex_offs.offset_bzero = (kptr_t)fi.find_bzero();
        v3ntex_offs.offset_bcopy = (kptr_t)fi.find_bcopy();
        v3ntex_offs.offset_copyin = (kptr_t)fi.find_copyin();
        v3ntex_offs.offset_copyout = (kptr_t)fi.find_copyout();
        v3ntex_offs.offset_ipc_port_alloc_special = (kptr_t)fi.find_ipc_port_alloc_special();
        v3ntex_offs.offset_ipc_kobject_set = (kptr_t)fi.find_ipc_kobject_set();
        v3ntex_offs.offset_ipc_port_make_send = (kptr_t)fi.find_ipc_port_make_send();
        v3ntex_offs.offset_rop_ldr_r0_r0_0xc = (kptr_t)fi.find_rop_ldr_x0_x0_0x10();
        v3ntex_offs.offset_chgproccnt = (kptr_t)fi.find_chgproccnt();
        v3ntex_offs.offset_kauth_cred_ref = (kptr_t)fi.find_kauth_cred_ref();
        v3ntex_offs.offset_OSSerializer_serialize = (kptr_t)fi.find_osserializer_serialize();
        LOG("Successfully found offsets for v3ntex with offsetfinder64.");
        return &v3ntex_offs;
    } catch (tihmstar::exception& e) {
        LOG("Failed to find offsets for v3ntex with offsetfinder64 with a non-fatal error. %d (%s).", e.code(), e.what());
        return NULL;
    } catch (std::exception& e) {
        LOG("Failed to find offsets for v3ntex with offsetfinder64 with a fatal error. %s.", e.what());
        return NULL;
    }
}
