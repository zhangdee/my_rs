
/*
 Module:
	Block coding specific header file
 Description:
	This Module define data structures for block coding. 
 Author:
	Developed by Songlin Song @ 20130113
 Modificaition:
    Modified by zhangdee @ 2015-11-17
	Modified by XXX @ XXX
 */

#ifndef _BLOCK_CODE_H_
#define _BLOCK_CODE_H_

#include "common.h"

/* program specific */
#define HEADER_SIZE                 5
#define CODE_OFFSET_BYTES           0
#define CODE_OFFSET_BITS            0
#define MAX_BLOCK_CODE_LEN          255     /* the max block code length (number of symbos) supported by this program */
#define MAX_HEADER_SIZE             0x20    /* 32 bytes each */
#define MAX_PACKET_SIZE             0x800   /* 2048 bytes each */


typedef void * fec_encoder_hdl;
typedef void * fec_decoder_hdl;


/* a block code encoder */
typedef struct {
    /* data buffer */
    unsigned char * header_buf[MAX_BLOCK_CODE_LEN];
    unsigned char * packets_buf[MAX_BLOCK_CODE_LEN];
    int packets_len[MAX_BLOCK_CODE_LEN];

    /* for block code encoding */
    bit_manipulater_t * bit_mnper[MAX_BLOCK_CODE_LEN];  /* bitstream manipulater */
    uint8_t * symbol_buf;                               /* block encode working buffer */

    /* private variables */
    int info_symbol_id;                     /* information ID in the code block, from 0 to (block_code_len - 1) */
    int code_word_flag;                     /* toggles between 0 and 1 */

    /* user arguments (DO NOT permit real-time modifying) */
    int block_code_len;
    int block_info_len;

    /* erasure encoder engine handle */
    void * erasure_coder;
} block_encoder_t;

/* a block code decoder */
typedef struct {

    /* receiving packets buffer */
    unsigned char * packets_buf[2][MAX_BLOCK_CODE_LEN];
    int packets_len[2][MAX_BLOCK_CODE_LEN];
    int ping_pong;                                      /* ping-pong index */

    /* for block code decoding */
    bit_manipulater_t bit_mnper[MAX_BLOCK_CODE_LEN];    /* bitstream manipulater */
    unsigned char * symbol_buf;                         /* block decode working buffer */

    /* user arguments */
    int cur_code_len;
    int cur_info_len;

    /* private variables */
    int cur_word_bit;
    int last_symbol_id;                                 /* the last accepted symbol num */
    int last_continuous_id;                             /* the highest symbol num which is continuous */
    int lost_pos[MAX_BLOCK_CODE_LEN];                   /* stores the DE-CUT lost positions */

    /* statistics */
    int block_lost_info;        // number of lost info symbols (packets) in the current code word
    int block_lost_check;       // number of lost check symbols (packets) in the current code word
    int recovered_info;         // number of recovered info symbols (packets) after block decoding
    int recovered_check;        // number of recovered check symbols (packets) after block decoding

    /* erasure decoder engine handle */
    void * erasure_coder;
    int erasure_coder_rst;
} block_decoder_t;

#endif
