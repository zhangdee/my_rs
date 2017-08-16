
#ifndef _TMS320C6X
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include "common.h"
#include "block_code.h"
#include "reed_solomon.h"


/* report level */
#define RPT_ERR (1) // error, system error
#define RPT_WRN (2) // warning, maybe wrong, maybe OK
#define RPT_INF (3) // important information
#define RPT_DBG (4) // debug information

static int rpt_lvl = RPT_WRN; /* report level: ERR, WRN, INF, DBG */

/* report micro */
#define RPT(lvl, ...) \
    do { \
        if(lvl <= rpt_lvl) { \
            switch(lvl) { \
                case RPT_ERR: \
                    fprintf(stderr, "\"%s\" line %d [err]: ", __FILE__, __LINE__); \
                    break; \
                case RPT_WRN: \
                    fprintf(stderr, "\"%s\" line %d [wrn]: ", __FILE__, __LINE__); \
                    break; \
                case RPT_INF: \
                    fprintf(stderr, "\"%s\" line %d [inf]: ", __FILE__, __LINE__); \
                    break; \
                case RPT_DBG: \
                    fprintf(stderr, "\"%s\" line %d [dbg]: ", __FILE__, __LINE__); \
                    break; \
                default: \
                    fprintf(stderr, "\"%s\" line %d [???]: ", __FILE__, __LINE__); \
                    break; \
                } \
                fprintf(stderr, __VA_ARGS__); \
                fprintf(stderr, "\n"); \
        } \
    } while(0)


rs_hdl rs_alloc();
void rs_free(rs_hdl rs);
int rs_reset(rs_hdl rs, int rs_code_len, int rs_info_len);
int reed_encode(intGF_t * info_symbol, intGF_t * check_symbol, rs_hdl rs_encoder);


static void block_encoding(block_encoder_t * block_encoder)
{
    reed_solomon_t * reed_solomon = (reed_solomon_t *)block_encoder->erasure_coder;
    bit_manipulater_t * bit_mnper;

    int info_len;               // number of info symbols in a code word
    int code_len;               // total number of symbols in a code word
    int decut_info_len;         // number of info symbols in a de-cut code word
    int decut_code_len;         // total number of symbols in a de-cut code word
    int check_len;              // number of check symblos in a code word
    int bits_per_symbol;

    int data_bits;              // length of the data buffer which is to be protected, in bits
    int data_symbols;           // number of symbols in the data buffer
    int max_data_size;          // the maximum size of the data, in byte
    int i, k;

    /* parameter check */
    if(block_encoder->block_code_len <= block_encoder->block_info_len)
    {
        return;
    }

    info_len = block_encoder->block_info_len;
    code_len = block_encoder->block_code_len;
    check_len = code_len - info_len;
    decut_code_len = reed_solomon->NN;
    decut_info_len = reed_solomon->KK;
    bits_per_symbol = reed_solomon->MM;

    ////////////////////////////////////////////////////////
    //  find out the maximum size of information packets  //
    //  and set to check packets                          //
    ////////////////////////////////////////////////////////

    max_data_size = 0;
    for(i = 0; i < info_len; i++)
    {
        if(block_encoder->packets_len[i] > max_data_size)
        {
            max_data_size = block_encoder->packets_len[i];
        }
    }

    data_bits = max_data_size * 8 - CODE_OFFSET_BITS;
    if(0 == data_bits % bits_per_symbol)
    {
        data_symbols = data_bits / bits_per_symbol;
    } else {
        data_symbols = data_bits / bits_per_symbol + 1;
        max_data_size += 1;
    }

    for(i = 0; i < check_len; i++)
    {
        block_encoder->packets_len[info_len + i] = max_data_size;
    }

    ////////////////////////////////////////////////////////
    //            initialize bits manipulater             //
    ////////////////////////////////////////////////////////

    // for information data buffers
    for(i = 0; i < info_len; i++)
    {
        bit_mnper = block_encoder->bit_mnper[i];

        bit_mnper->oriPtr = block_encoder->packets_buf[i];
        bit_mnper->curPtr = block_encoder->packets_buf[i];
        bit_mnper->leftBits = 8 - CODE_OFFSET_BITS;
        bit_mnper->nSize = block_encoder->packets_len[i] * 8 - CODE_OFFSET_BITS;
        bit_mnper->curPos = 0;
    }

    // for check data buffers
    for(i = 0; i < check_len; i++)
    {
        bit_mnper = block_encoder->bit_mnper[decut_info_len + i];

        bit_mnper->oriPtr = block_encoder->packets_buf[info_len + i];
        bit_mnper->curPtr = block_encoder->packets_buf[info_len + i];
        bit_mnper->leftBits = 8 - CODE_OFFSET_BITS;
        bit_mnper->nSize = block_encoder->packets_len[info_len + i] * 8 - CODE_OFFSET_BITS;
        bit_mnper->curPos = 0;
    }

    ////////////////////////////////////////////////////////
    //                block code encoding                 //
    ////////////////////////////////////////////////////////

    for(k = data_symbols; k > 0; --k)
    {
        memset(block_encoder->symbol_buf, 0x00, MAX_BLOCK_CODE_LEN * sizeof(unsigned char));

        for(i = 0; i < info_len; i++)
        {
            get_next_symbol(block_encoder->bit_mnper[i], block_encoder->symbol_buf + i, bits_per_symbol);
        }

        reed_encode(block_encoder->symbol_buf, block_encoder->symbol_buf + decut_info_len,
                    (reed_solomon_t *)(block_encoder->erasure_coder));

        for(i = decut_info_len; i < decut_code_len; i++)
        {
            set_next_symbol(block_encoder->bit_mnper[i], block_encoder->symbol_buf[i], bits_per_symbol);
        }
    }

}


void block_encoder_destroy(fec_encoder_hdl fec_encoder)
{
    block_encoder_t * block_encoder;
    int i;

    if(NULL != fec_encoder)
    {
        block_encoder = (block_encoder_t *)fec_encoder;

        for(i = 0; i < MAX_BLOCK_CODE_LEN; i++)
        {
            if(NULL != block_encoder->header_buf[i])
            {
                free(block_encoder->header_buf[i]);
            }

            if(NULL != block_encoder->packets_buf[i])
            {
                free(block_encoder->packets_buf[i]);
            }

        }

        for(i = 0; i < MAX_BLOCK_CODE_LEN; i++)
        {
            if(NULL != block_encoder->bit_mnper[i])
            {
                free(block_encoder->bit_mnper[i]);
            }
        }

        if(NULL != block_encoder->erasure_coder)
        {
            rs_free(block_encoder->erasure_coder);
        }

        if(NULL != block_encoder->symbol_buf)
        {
            free(block_encoder->symbol_buf);
        }

        free(block_encoder);
    }
}

fec_encoder_hdl block_encoder_create()
{
    block_encoder_t * block_encoder = NULL;
    int i;

    /* block-code encoder instance */
    block_encoder = (block_encoder_t *)malloc(sizeof(block_encoder_t));
    if(NULL == block_encoder)
    {
        goto err_clear;
    }

    memset((void *)block_encoder, 0, sizeof(block_encoder_t));

    /* data storage buffer */
    for(i = 0; i < MAX_BLOCK_CODE_LEN; i++)
    {
        block_encoder->header_buf[i] = (unsigned char *)malloc((MAX_HEADER_SIZE + 0x100) * sizeof(unsigned char));
        if(NULL == block_encoder->header_buf[i])
        {
            goto err_clear;
        }
    }

    for(i = 0; i < MAX_BLOCK_CODE_LEN; i++)
    {
        block_encoder->packets_buf[i] = (unsigned char *)malloc((MAX_PACKET_SIZE + 0x100) * sizeof(unsigned char));
        if(NULL == block_encoder->packets_buf[i])
        {
            goto err_clear;
        }
    }

    /* bit manipulater and symbol buffer */
    for(i = 0; i < MAX_BLOCK_CODE_LEN; i++)
    {
        block_encoder->bit_mnper[i] = (bit_manipulater_t *)malloc(sizeof(bit_manipulater_t));
        if(NULL == block_encoder->bit_mnper[i])
        {
            goto err_clear;
        }
    }

    block_encoder->symbol_buf = (uint8_t *)malloc(MAX_BLOCK_CODE_LEN * sizeof(uint8_t));
    if(NULL == block_encoder->symbol_buf)
    {
        goto err_clear;
    }

    /* private variables */
    block_encoder->info_symbol_id = 0;
    block_encoder->code_word_flag = 1;

    /* user arguments */
    block_encoder->block_code_len = 1;
    block_encoder->block_info_len = 1;

    /* block-code algorithm engine handle */
    block_encoder->erasure_coder = rs_alloc();
    if(NULL == block_encoder->erasure_coder)
    {
        goto err_clear;
    }

    return (fec_encoder_hdl)block_encoder;

err_clear:
    block_encoder_destroy((fec_encoder_hdl *)block_encoder);
    RPT(RPT_ERR, "create block-code encoder instance failed!\n");
    return NULL;
}

/*******************************************************************************
 * return:
 *   0: run success
 *   nagetive value: run failed
 */
int block_encoder_reset(fec_encoder_hdl fec_encoder, int fec_code_len, int fec_info_len)
{
    block_encoder_t * block_encoder;

    if(NULL == fec_encoder)
    {
        RPT(RPT_ERR, "block-code encoder reset failed due to NULL instance handle!\n");
        return -1;
    } else {
        block_encoder = (block_encoder_t *)fec_encoder;
    }

    if(fec_code_len > MAX_BLOCK_CODE_LEN)
    {
        fec_code_len = MAX_BLOCK_CODE_LEN;
    }

    if((fec_info_len < 1) || (fec_code_len < 1))
    {
        fec_info_len = 1;
        fec_code_len = 1;
    }

    if(fec_info_len >= fec_code_len)
    {
        fec_info_len = 1;
        fec_code_len = 1;
    }

    /* private variables */
    block_encoder->info_symbol_id = 0;
    block_encoder->code_word_flag ^= 0x1;     // block_encoder->code_word_flag toggles

    // user arguments
    block_encoder->block_code_len = fec_code_len;
    block_encoder->block_info_len = fec_info_len;

    /* erasure encoder */
    if(0 == rs_reset(block_encoder->erasure_coder, fec_code_len, fec_info_len))
    {
        RPT(RPT_INF, "reset block-code encoder with new parameters (%d, %d)\n", fec_code_len, fec_info_len);
    } else {
        RPT(RPT_ERR, "reset block-code encoder failed!\n");
        return -1;
    }

    return 0;
}

/*******************************************************************************
 * return:
 *   non-negative value: make block coding header sucessfully and return header's length (byte)
 *   negative value: failed
 */
int block_enc_make_header(fec_encoder_hdl fec_encoder, uint8_t * header_buf, const int source_len)
{
    block_encoder_t * block_encoder;

    /* check */
    if(NULL == fec_encoder)
    {
        RPT(RPT_ERR, "NULL fec_encoder\n");
        return -1;
    } else {
        block_encoder = (block_encoder_t *)fec_encoder;
    }

    if(NULL == header_buf)
    {
        RPT(RPT_ERR, "NULL header buffer!\n");
    }

    /* make block coding header */
    set_block_code_len(header_buf, block_encoder->block_code_len);
    set_block_info_len(header_buf, block_encoder->block_info_len);
    set_symbol_num(header_buf, block_encoder->info_symbol_id);
    set_toggle_bit(header_buf, block_encoder->code_word_flag);
    set_packet_len(header_buf, source_len);

    /* update info symbol counter and code block toggle flag */
    block_encoder->info_symbol_id++;

    if(block_encoder->info_symbol_id == block_encoder->block_info_len)
    {
        block_encoder->info_symbol_id = 0;
        block_encoder->code_word_flag ^= 0x01;
    }

    /* return the block coding header size */
    return HEADER_SIZE;
}

/*******************************************************************************
 * return:
 *   positive value: generate check data packets and return there quantity
 *   zero: do not generate check data packets
 *   negative value: run failed
 */
int block_enc_process(fec_encoder_hdl fec_encoder, uint8_t * const source_header, uint8_t * const source_data,
                      uint8_t *** out_header, uint8_t *** out_data, int ** out_len)
{
    block_encoder_t * block_encoder;
    unsigned char * header_buf;
    int info_symbol_id;
    int block_toggle_flag;
    int info_packet_len;
    int i;

    /* check */
    if(NULL == fec_encoder)
    {
        RPT(RPT_ERR, "NULL fec_encoder\n");
        return -1;
    } else {
        block_encoder = (block_encoder_t *)fec_encoder;
    }

    if((NULL == source_header) || (NULL == source_data))
    {
        RPT(RPT_ERR, "NULL source_header or source_data!\n");
        return -1;
    }

    if((NULL == out_header) || (NULL == out_data) || (NULL == out_len))
    {
        RPT(RPT_ERR, "NULL return pointers!\n");
        return -1;
    }

    /* parameter check */
    if(block_encoder->block_code_len <= block_encoder->block_info_len)
    {
        return 0;
    }

    /* get info symbol ID and the length of symbol packet */
    info_symbol_id = get_symbol_num(source_header);
    block_toggle_flag = get_toggle_bit(source_header);
    info_packet_len = get_packet_len(source_header);

    /* copy information symbol packet data and set length */
    memcpy(block_encoder->packets_buf[info_symbol_id], source_data, info_packet_len);
    block_encoder->packets_len[info_symbol_id] = info_packet_len;

    /* block code encoding */
    if(info_symbol_id + 1 == block_encoder->block_info_len)
    {
        block_encoding(block_encoder);

        /* make header for check symbol packet */
        for(i = block_encoder->block_info_len; i < block_encoder->block_code_len; i++)
        {
            header_buf = block_encoder->header_buf[i];
            set_block_code_len(header_buf, block_encoder->block_code_len);
            set_block_info_len(header_buf, block_encoder->block_info_len);
            set_symbol_num(header_buf, i);
            set_toggle_bit(header_buf, block_toggle_flag);
            set_packet_len(header_buf, block_encoder->packets_len[i]);
        }

        /* return the check packets' header, data and length */
        *out_header = block_encoder->header_buf + block_encoder->block_info_len;
        *out_data = block_encoder->packets_buf + block_encoder->block_info_len;
        *out_len = block_encoder->packets_len + block_encoder->block_info_len;

        return (block_encoder->block_code_len - block_encoder->block_info_len);
    } else {
        return 0;
    }
}

