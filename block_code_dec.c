
#include <math.h>
#include <stdlib.h>
#include <string.h>

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
void rs_free(void * ptr);
int rs_reset(rs_hdl rs, int rs_code_len, int rs_info_len);
int rs_decode(rs_hdl rs, unsigned char * data, int * eras_pos, int no_eras);

static void block_decoding(block_decoder_t * block_decoder)
{
    unsigned char ** packets_buf = block_decoder->packets_buf[block_decoder->ping_pong];
    int * packets_len = block_decoder->packets_len[block_decoder->ping_pong];
    reed_solomon_t * reed_solomon = (reed_solomon_t *)(block_decoder->erasure_coder);

    int code_len, info_len, cut_len, decut_code_len, decut_info_len;
    int bits_per_symbol, num_symbols;
    int check_packet_size = 0;
    int num_lost_nodes = 0;
    int i, k;

    /* do not need to decode when no info packets were lost */
    if(block_decoder->last_continuous_id >= block_decoder->cur_info_len - 1)
    {
        return;
    }

    ////////////////////////////////////////////////////////////////
    //                       preparations                         //
    ////////////////////////////////////////////////////////////////

    code_len = block_decoder->cur_code_len;
    info_len = block_decoder->cur_info_len;
    decut_code_len = reed_solomon->NN;
    decut_info_len = reed_solomon->KK;
    cut_len = decut_code_len - code_len;

    for(i = 0; i < decut_code_len; i++)
    {
        block_decoder->lost_pos[i] = 0;
    }

    block_decoder->block_lost_info = 0;
    block_decoder->block_lost_check = 0;
    block_decoder->recovered_info = 0;
    block_decoder->recovered_check = 0;

    ////////////////////////////////////////////////////////////////
    //                   Get lost information                     //
    ////////////////////////////////////////////////////////////////

    for(i = 0; i < code_len; i++)
    {
        if((i >= info_len) && (packets_len[i] > 0))
        {
            check_packet_size = packets_len[i];
        }

        if(0 == packets_len[i])
        {
            if(i < info_len)
            {
                block_decoder->lost_pos[num_lost_nodes++] = i;
                block_decoder->block_lost_info ++;
            } else {
                block_decoder->lost_pos[num_lost_nodes++] = i + cut_len;
                block_decoder->block_lost_check ++;
            }
        }
    }

    ////////////////////////////////////////////////////////////////
    //        do block code decoding if the number of lost        //
    //       packet is within the block decoding capability       //
    ////////////////////////////////////////////////////////////////

    if(num_lost_nodes <= code_len - info_len)   /* note: when code_len equals to info_len (no check), do nothing */
    {
        /* init the bit manipulator */
        for(i = 0; i < code_len; i++)
        {
            block_decoder->bit_mnper[i].oriPtr = packets_buf[i] + CODE_OFFSET_BYTES;
            block_decoder->bit_mnper[i].curPtr = packets_buf[i] + CODE_OFFSET_BYTES;
            block_decoder->bit_mnper[i].curPos = 0;
            block_decoder->bit_mnper[i].leftBits = 8 - CODE_OFFSET_BITS;
            if(0 == packets_len[i])
            {
                block_decoder->bit_mnper[i].nSize = (check_packet_size - CODE_OFFSET_BYTES) * 8 - CODE_OFFSET_BITS;
            } else {
                block_decoder->bit_mnper[i].nSize = (packets_len[i] - CODE_OFFSET_BYTES) * 8 - CODE_OFFSET_BITS;
            }
        }

        /* block code decoding */
        bits_per_symbol = reed_solomon->MM;
        num_symbols = ((check_packet_size - CODE_OFFSET_BYTES) * 8 - CODE_OFFSET_BITS) / bits_per_symbol;

        for(k = 0; k < num_symbols; ++k)
        {
            memset(block_decoder->symbol_buf, 0, decut_code_len);

            for(i = 0; i < code_len; ++i)
            {
                if(0 != packets_len[i])
                {
                    if(i < info_len)
                    {
                        get_next_symbol(&(block_decoder->bit_mnper[i]), block_decoder->symbol_buf + i, bits_per_symbol);
                    } else {
                        get_next_symbol(&(block_decoder->bit_mnper[i]), block_decoder->symbol_buf + i + cut_len, bits_per_symbol);
                    }
                }
            }

            rs_decode((reed_solomon_t *)(block_decoder->erasure_coder), block_decoder->symbol_buf,
                      block_decoder->lost_pos, num_lost_nodes);

            for(i = 0; i < info_len; ++i)
            {
                if(0 == packets_len[i])
                {
                    set_next_symbol(&(block_decoder->bit_mnper[i]), block_decoder->symbol_buf[i], bits_per_symbol);
                }
            }
        }

        for(i = 0; i < info_len; i++)
        {
            if(0 == packets_len[i])
            {
                packets_len[i] = check_packet_size;     // set recovered packets' size with check packets'
            }
        }
    }
#if 0
    else {
        if(num_lost_nodes > rs_code_len - rs_info_len)
        {
            printf("\nnum of lost packets exceeds RS capability ! \
                    \nlost packets: %d, RS check packet: %d", num_lost_nodes, rs_code_len - rs_info_len);
        }
    }
#endif

    return;
}

void block_decoder_destroy(fec_decoder_hdl fec_decoder)
{
    block_decoder_t * block_decoder = (block_decoder_t *)fec_decoder;
    int i, j;

    if(NULL != block_decoder)
    {
        for(j = 0; j < 2; j++)
        {
            for(i = 0; i < MAX_BLOCK_CODE_LEN; i++)
            {
                if(NULL != block_decoder->packets_buf[j][i])
                {
                    free(block_decoder->packets_buf[j][i]);
                }
            }
        }

        if(NULL != block_decoder->symbol_buf)
        {
            free(block_decoder->symbol_buf);
        }

        rs_free(block_decoder->erasure_coder);

        free(block_decoder);
    }
}

fec_decoder_hdl block_decoder_create()
{
    block_decoder_t * block_decoder;
    int i, j;

    block_decoder = (block_decoder_t *)malloc(sizeof(block_decoder_t));
    if(NULL == block_decoder)
    {
        goto err_clear;
    }

    ////////////////////////////////////////////////////////
    //              receiving packets buffer              //
    ////////////////////////////////////////////////////////

    for(j = 0; j < 2; j++)
    {
        for(i = 0; i < MAX_BLOCK_CODE_LEN; i++)
        {
            block_decoder->packets_buf[j][i] = (unsigned char *)malloc(MAX_PACKET_SIZE * sizeof(unsigned char));
            if(NULL == block_decoder->packets_buf[j][i])
            {
                goto err_clear;
            }

            block_decoder->packets_len[j][i] = 0;
        }
    }

    block_decoder->ping_pong = 0;

    ////////////////////////////////////////////////////////
    //              for block code decoding               //
    ////////////////////////////////////////////////////////

    for(i = 0; i < MAX_BLOCK_CODE_LEN; i++)
    {
        block_decoder->bit_mnper[i].oriPtr = NULL;
        block_decoder->bit_mnper[i].curPtr = NULL;
        block_decoder->bit_mnper[i].curPos = 0;
        block_decoder->bit_mnper[i].leftBits = 8;
        block_decoder->bit_mnper[i].nSize = 0;
    }

    block_decoder->symbol_buf = (unsigned char *)malloc(MAX_BLOCK_CODE_LEN * sizeof(unsigned char));
    if(NULL == block_decoder->symbol_buf)
    {
        goto err_clear;
    }

    ////////////////////////////////////////////////////////
    //                   user arguments                   //
    ////////////////////////////////////////////////////////

    block_decoder->cur_code_len = 1;
    block_decoder->cur_info_len = 1;

    ////////////////////////////////////////////////////////
    //                 private variables                  //
    ////////////////////////////////////////////////////////

    block_decoder->cur_word_bit = 0;
    block_decoder->last_symbol_id = -1;
    block_decoder->last_continuous_id = -1;

    for(i = 0; i < MAX_BLOCK_CODE_LEN; i++)
    {
        block_decoder->lost_pos[i] = 0;
    }

    ////////////////////////////////////////////////////////
    //                     statistics                     //
    ////////////////////////////////////////////////////////

    block_decoder->block_lost_info = 0;
    block_decoder->block_lost_check = 0;
    block_decoder->recovered_info = 0;
    block_decoder->recovered_check = 0;

    /* erasure decoder engine */
    block_decoder->erasure_coder = rs_alloc();
    if(NULL == block_decoder->erasure_coder)
    {
        goto err_clear;
    }

    if(0 > rs_reset(block_decoder->erasure_coder, 1, 1))
    {
        goto err_clear;
    }

    block_decoder->erasure_coder_rst = 0;

    return (fec_decoder_hdl)block_decoder;

err_clear:
    block_decoder_destroy((fec_decoder_hdl *)block_decoder);
    RPT(RPT_ERR, "create block-code decoder instance failed!\n");
    return NULL;
}

/*******************************************************************************
 * return:
 *   0: run success
 *   nagetive value: run failed
 */
int block_decoder_reset(fec_decoder_hdl fec_decoder, int code_len, int info_len)
{
    block_decoder_t * block_decoder;
    int i;

    if(NULL == fec_decoder)
    {
        RPT(RPT_ERR, "block-code decoder reset failed due to NULL instance handle!\n");
        return -1;
    } else {
        block_decoder = (block_decoder_t *)fec_decoder;
    }

    ////////////////////////////////////////////////////////
    //              for block code decoding               //
    ////////////////////////////////////////////////////////

    for(i = 0; i < MAX_BLOCK_CODE_LEN; i++)
    {
        block_decoder->bit_mnper[i].oriPtr = NULL;
        block_decoder->bit_mnper[i].curPtr = NULL;
        block_decoder->bit_mnper[i].curPos = 0;
        block_decoder->bit_mnper[i].leftBits = 8;
        block_decoder->bit_mnper[i].nSize = 0;
    }

    memset(block_decoder->symbol_buf, 0, MAX_BLOCK_CODE_LEN * sizeof(unsigned char));

    ////////////////////////////////////////////////////////
    //                   user arguments                   //
    ////////////////////////////////////////////////////////

    block_decoder->cur_code_len = code_len;
    block_decoder->cur_info_len = info_len;

    ////////////////////////////////////////////////////////
    //                 private variables                  //
    ////////////////////////////////////////////////////////

    block_decoder->last_symbol_id = -1;
    block_decoder->last_continuous_id = -1;

    for(i = 0; i < MAX_BLOCK_CODE_LEN; i++)
    {
        block_decoder->lost_pos[i] = 0;
    }

    ////////////////////////////////////////////////////////
    //                     statistics                     //
    ////////////////////////////////////////////////////////

    block_decoder->block_lost_info = 0;
    block_decoder->block_lost_check = 0;
    block_decoder->recovered_info = 0;
    block_decoder->recovered_check = 0;

    /* erasure decoder */
    if(0 == rs_reset(block_decoder->erasure_coder, code_len, info_len))
    {
        RPT(RPT_INF, "reset block-code decoder with new parameters (%d, %d)\n", code_len, info_len);
        block_decoder->erasure_coder_rst = 0;
    } else {
        RPT(RPT_ERR, "reset block-code decoder failed!\n");
        return -1;
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////////

static int check_dec(block_decoder_t * block_decoder, int new_code_len, int new_info_len,
                         int new_symbol_num, int new_toggle_bit)
{
    int dec = 0;

    /* case 1: new packet's block info length or code length changes */
    if((new_code_len != block_decoder->cur_code_len) || (new_info_len != block_decoder->cur_info_len))
    {
        block_decoder->erasure_coder_rst = 1;   // remember this, reset erasure coder after decoding the current code word
        dec = 1;
    }

    /* case 2: explicit code word alternation */
    if(new_toggle_bit != block_decoder->cur_word_bit)
    {
        dec = 1;
    }

    /* case3: an exceptive code word alternation: symbol number goes backward
       while toggle bit not toggles */
    if(new_symbol_num <= block_decoder->last_symbol_id)
    {
        dec = 1;
    }

    return dec;
}

static int check_input(block_decoder_t * block_decoder, int new_symbol_num)
{
    int ret = 0;

    /* info packets must be accepted */
    if(new_symbol_num < block_decoder->cur_info_len)
    {
        ret = 1;
    }
    /* check packets must be accepted when there are packets loss */
    else if(block_decoder->last_continuous_id < block_decoder->cur_info_len - 1)
    {
        ret = 1;
    }

    return ret;
}

/*******************************************************************************
 * return:
 *   non negative value: run success and return the packet length (byte)
 *   nagetive value: run failed
 */
int block_dec_parse_len(uint8_t * header_buf)
{
    if(NULL == header_buf)
    {
        RPT(RPT_ERR, "NULL header buffer!\n");
        return -1;
    } else {
        return get_packet_len(header_buf);
    }
}


/*******************************************************************************
 * return:
 *   positive value: output info data packets and return there quantity
 *   zero: do not output info data packets
 *   negative value: run failed
 */
int block_dec_process(fec_decoder_hdl fec_decoder, uint8_t * const source_header,
                      uint8_t * const packet_data, uint8_t *** out_data, int ** out_len)
{
    block_decoder_t * block_decoder;

    int new_code_len;
    int new_info_len;
    int new_symbol_id;
    int new_toggle_bit;
    int packet_len;

    int output_num = 0;
    int i;

    /* check */
    if(NULL == fec_decoder)
    {
        RPT(RPT_ERR, "NULL fec_decoder\n");
        return -1;
    } else {
        block_decoder = (block_decoder_t *)fec_decoder;
    }

    if((NULL == source_header) || (NULL == packet_data))
    {
        RPT(RPT_ERR, "NULL source_header or packet_data!\n");
        return -1;
    }

    if((NULL == out_data) || (NULL == out_len))
    {
        RPT(RPT_ERR, "NULL return pointers!\n");
        return -1;
    }

    ////////////////////////////////////////////////////////////////
    //        check and do block code decoding arrcording         //
    //           to the new packet's header information           //
    ////////////////////////////////////////////////////////////////

    new_code_len = get_block_code_len(source_header);
    new_info_len = get_block_info_len(source_header);
    new_symbol_id = get_symbol_num(source_header);
    new_toggle_bit = get_toggle_bit(source_header);
    packet_len = get_packet_len(source_header);

    if(check_dec(block_decoder, new_code_len, new_info_len, new_symbol_id, new_toggle_bit))
    {
        /* block code decoding of the last code word */
        block_decoding(block_decoder);

        /* output */
        *out_data = block_decoder->packets_buf[block_decoder->ping_pong];
        *out_len = block_decoder->packets_len[block_decoder->ping_pong];
        output_num = block_decoder->cur_info_len;

        /* reset block code decoder, receiving packets buffer,
           ping-pong counter and other variables */
        if(block_decoder->erasure_coder_rst)
        {
            block_decoder_reset(fec_decoder, new_code_len, new_info_len);
        }

        block_decoder->ping_pong ^= 0x1;

        for(i = 0; i < MAX_BLOCK_CODE_LEN; i++)
        {
            block_decoder->packets_len[block_decoder->ping_pong][i] = 0;
        }

        block_decoder->cur_word_bit = new_toggle_bit;
        block_decoder->last_symbol_id = -1;
        block_decoder->last_continuous_id = -1;
    }

    ////////////////////////////////////////////////////////////////
    //     handle the new received packet (either belongs to      //
    //      the current code word or starts a new code word)      //
    ////////////////////////////////////////////////////////////////

    if(check_input(block_decoder, new_symbol_id))
    {
        /* copy to working packets buffer */
        memcpy(block_decoder->packets_buf[block_decoder->ping_pong][new_symbol_id], packet_data, packet_len);
        block_decoder->packets_len[block_decoder->ping_pong][new_symbol_id] = packet_len;

        /* update the buffer's index */
        block_decoder->last_symbol_id = new_symbol_id;

        /* if the input packet is continuous, output immediately */
        if((block_decoder->last_continuous_id + 1) == new_symbol_id)
        {
            block_decoder->last_continuous_id++;
        }
    }

    return output_num;
}

