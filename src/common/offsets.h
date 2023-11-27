// SPDX-License-Identifier: GPL-2.0+
#pragma once

#include "vmlinux.h"

/* CRC64 of "loaded"  */
const u64 CRC_LOADED = 0xec6642829d632573;

/* CRC64 of task_struct->real_parent */
const u64 CRC_TASK_STRUCT_REAL_PARENT = 0x940b92aaad4c5437;

/* CRC64 of task_struct->pid */
const u64 CRC_TASK_STRUCT_PID = 0xc713ffcffcd1cc3c;

/* CRC64 of task_struct->tgid */
const u64 CRC_TASK_STRUCT_TGID = 0x68bd2d49cb6f7dd5;

/* CRC64 of task_struct->loginuid */
const u64 CRC_TASK_STRUCT_LOGINUID = 0x9951a3e4f7757060;

/* task_struct->mm */
const u64 CRC_TASK_STRUCT_MM = 0xce718bb9d7fe31a2;

/* mm_struct->exe_file */
const u64 CRC_MM_STRUCT_EXE_FILE = 0x3ac4a1974916ed95;

/* mm_struct->arg_start */
const u64 CRC_MM_STRUCT_ARG_START = 0xbf4ac23cfb9bfcdc;

/* mm_struct->arg_end */
const u64 CRC_MM_STRUCT_ARG_END = 0x5a7beb317405d4d2;

/* file->f_path */
const u64 CRC_FILE_F_PATH = 0xf1d5510f86260be;

/* path->dentry */
const u64 CRC_PATH_DENTRY = 0x71a4a97d6a6791a9;

/* path->mnt */
const u64 CRC_PATH_MNT = 0x88c40f5cf27266ae;

/* dentry->d_name */
const u64 CRC_DENTRY_D_NAME = 0x1b807e513eab1323;

/* dentry->d_inode */
const u64 CRC_DENTRY_D_INODE = 0x3A4154E1EBE3C516;

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

/* inode->fs */
const u64 CRC_INODE_FS = 0x61ac74b5c543f248;

/* inode->i_sb */
const u64 CRC_INODE_I_SB = 0x861dc69e083a70b5;

/* inode->i_mode */
const u64 CRC_INODE_I_MODE = 0xC3ECA32D8DB5FBC3;

/* inode->i_uid */
const u64 CRC_INODE_I_UID = 0x70149101D7E8C934;

/* inode->i_gid */
const u64 CRC_INODE_I_GID = 0x5353E0ECE03150E1;

/* super_block->s_dev */
const u64 CRC_SBLOCK_S_DEV = 0xb1c03bec387e1aca;

/* task_struct->fs */
const u64 CRC_TASK_STRUCT_FS = 0x7e927c27fc9f401f;

/* fs_struct->pwd */
const u64 CRC_FS_STRUCT_PWD = 0xc5d27f658a888649;

/* dentry->d_parent */
const u64 CRC_DENTRY_D_PARENT = 0x7f8acf45f8bb14fa;

/* qstr->len */
const u64 CRC_QSTR_LEN = 0xce592db861f9588;

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

/* sk_buff->mac_header */
const u64 CRC_SKBUFF_MAC_HDR = 0xd67d00581d6ed4cc;

/* linux_binprm->file */
const u64 CRC_LINUX_BINPRM_FILE = 0x323e974b140d6eff;

/* linux_binprm->filename */
const u64 CRC_LINUX_BINPRM_FILENAME = 0xb583ce53935255c5;

/* linux_binprm->interp */
const u64 CRC_LINUX_BINPRM_INTERP = 0x9f4cedeb0b40dc2c;

/* mount->mnt */
const u64 CRC_MOUNT_MNT = 0x332c1523b7204177;

/* mount->mnt_mountpoint */
const u64 CRC_MOUNT_MOUNTPOINT = 0x497e95c14e2d950;

/* mount->mnt_parent */
const u64 CRC_MOUNT_MNTPARENT = 0x57a4eea49a711d75;

/* vfsmount->mnt_root */
const u64 CRC_VFSMOUNT_MNTROOT = 0xe4baf16bf0b472fa;

/* task_struct->audit */
const u64 CRC_TASK_STRUCT_AUDIT = 0x67da4ab26d333059;

/* audit_task_info->loginuid */
const u64 CRC_AUDIT_TASK_INFO_LOGINUID = 0xe6dd107ea26da1a0;

/* LINUX_KERNEL_VERSION */
const u64 CRC_LINUX_KERNEL_VERSION = 0xbd0860b98f6d2ade;
