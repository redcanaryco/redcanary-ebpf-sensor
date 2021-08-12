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

/* inode->fs */
const u64 CRC_INODE_FS = 0x61ac74b5c543f248;

/* task_struct->fs */
const u64 CRC_TASK_STRUCT_FS = 0x7e927c27fc9f401f;

/* fs_struct->pwd */
const u64 CRC_FS_STRUCT_PWD = 0xc5d27f658a888649;

/* dentry->d_parent */
const u64 CRC_DENTRY_D_PARENT = 0x7f8acf45f8bb14fa;

/* qstr->len */
const u64 CRC_QSTR_LEN = 0xce592db861f9588;