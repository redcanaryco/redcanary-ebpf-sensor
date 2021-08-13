// SPDX-License-Identifier: GPL-2.0+
#pragma once

/* CRC64 of "loaded"  */
const u64 CRC_LOADED = 0xec6642829d632573;

/* CRC64 of task_struct->real_parent */
const u64 CRC_TASK_STRUCT_REAL_PARENT = 0x940b92aaad4c5437;

/* CRC64 of task_struct->pid */
const u64 CRC_TASK_STRUCT_PID = 0xc713ffcffcd1cc3c;

/* CRC64 of task_struct->loginuid */
const u64 CRC_TASK_STRUCT_LOGINUID = 0x9951a3e4f7757060;

/* task_struct->mm */
const u64 CRC_TASK_STRUCT_MM = 0xce718bb9d7fe31a2;

/* mm_struct->exe_file */
const u64 CRC_MM_STRUCT_EXE_FILE = 0x3ac4a1974916ed95;

/* file->f_path */
const u64 CRC_FILE_F_PATH = 0xf1d5510f86260be;

/* path->dentry */
const u64 CRC_PATH_DENTRY = 0x71a4a97d6a6791a9;

/* dentry->d_name */
const u64 CRC_DENTRY_D_NAME = 0x1b807e513eab1323;

/* qstr->hash_len */
const u64 CRC_QSTR_HASH_LEN = 0xeb88a6081906b367;

/* qstr->name */
const u64 CRC_QSTR_NAME = 0x8f5975ec8033153c;

/* file->f_inode */
const u64 CRC_FILE_F_INODE = 0xad18ad97f6aef632;

/* inode->i_rdev */
const u64 CRC_INODE_I_RDEV = 0x51b3c613c3a6c688;

/* inode->i_ino */
const u64 CRC_INODE_I_INO = 0xa9a6f8a386ba140e;

/* sk_buff->head */
const u64 CRC_SKBUFF_HEAD = 0xffd66a9e550dcbac;

/* sk_buff->transport_header */
const u64 CRC_TRANSPORT_HDR = 0xeff48bcd3179818c;

/* sk_buff->network_header */
const u64 CRC_NETWORK_HDR = 0x94847ef2e8239ef0;

/* sock_common->sk_family */
const u64 CRC_SOCK_COMMON_FAMILY = 0x58cc07362e5acf26;

/* sock_common->skc_daddr */
const u64 CRC_SOCK_COMMON_DADDR = 0xb8a7fa611ded721c;

/* sock_common->skc_rcv_saddr */
const u64 CRC_SOCK_COMMON_SADDR = 0x1e84b894d59120b4;

/* sock_common->skc_dport */
const u64 CRC_SOCK_COMMON_DPORT = 0x5fad6a2ba671e214;

/* sock_common->skc_num */
const u64 CRC_SOCK_COMMON_SPORT = 0xe962a62fbff22f42;

/* sock_common->skc_v6_daddr */
const u64 CRC_SOCK_COMMON_DADDR6 = 0x726604a3fe67d262;

/* sock_common->skc_v6_rcv_saddr */
const u64 CRC_SOCK_COMMON_SADDR6 = 0xb7848cfc7c751cae;

/* sk_buff->protocol */
const u64 CRC_SKBUFF_PROTO = 0x42a761c8a2a2b084;
