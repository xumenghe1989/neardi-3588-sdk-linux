/******************************************************************************
 *
 *  Copyright (C) 2020-2023 SeekWave Technology
 *
 *
 ******************************************************************************/

#ifndef __SKW_COMMON_H__
#define __SKW_COMMON_H__


#define BT_HCI_LOG_EN  0
#define BT_CP_LOG_EN   0

#define INCLUDE_NEW_VERSION 1

#define MAX_BT_LOG_SIZE (5*1024*1024) //500M


#define SEEKWAVE_BT_LOG_PATH     "/mnt/skwbt"
#define NV_FILE_NAME             "sv6160.nvbin"
#define NV_FILE_NAME_6316        "sv6316.nvbin"

//#define BD_ADDR_FILE_PATH        ""


#define BD_ADDR_LEN 6


#define skwbt_log(format, ...) pr_info("[SKWBT] %s: "format, __func__, ##__VA_ARGS__)

#define SKW_CHIPID_6316 0x5301
#define SKW_CHIPID_6160 0x0017



typedef struct{
	uint8_t  type;
	uint8_t  evt_op;
	uint8_t  len;
	uint8_t  nums;
	uint16_t cmd_op;
	uint8_t  status;
}hci_cmd_cmpl_evt_st;


ssize_t skw_file_write(struct file *, const void *, size_t);

ssize_t skw_file_read(struct file *fp, void *buf, size_t len);

char skw_file_copy(char *scr_file, char *des_file);

void skw_bd_addr_gen_init(void);

char skw_get_bd_addr(unsigned char *buffer);



#endif
