/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

/* Copyright 2018, Firmware Modules Inc. Licensed under the BSD 2-clause license. */

#include "uecc.h"

#include <stdio.h>
#include <string.h>
#include "sys/clock.h"
#include "dev/watchdog.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "Main"
#define LOG_LEVEL LOG_LEVEL_MAIN
/*---------------------------------------------------------------------------*/


static uint64_t g_rand = 88172645463325252ull;
int fake_rng(uint8_t *p_dest, unsigned p_size)
{
    while(p_size)
    {
        g_rand ^= (g_rand << 13);
        g_rand ^= (g_rand >> 7);
        g_rand ^= (g_rand << 17);

        unsigned l_amount = (p_size > 8 ? 8 : p_size);
        memcpy(p_dest, &g_rand, l_amount);
        p_size -= l_amount;
    }
    return 1;
}

#define NUM_ITER  32

static void print_hex(uint8_t* buf, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}


void uecc_test()
{

    uECC_set_rng(&fake_rng);

    uint8_t l_public[uECC_BYTES*2];
    uint8_t l_private[uECC_BYTES];

    uint8_t l_hash[uECC_BYTES];

    uint8_t l_sig[uECC_BYTES*2];

    int i;

    int min = 0xFFFFFFFF;
    int max = 0;
    uint64_t accum = 0;

    printf("Micro ECC Configuration:\n");
    printf("  uECC_CURVE=%d\n", uECC_CURVE);
    printf("  uECC_ASM=%d\n", uECC_ASM);
    printf("  uECC_BYTES=%d\n", uECC_BYTES);

    printf("Testing Micro ECC 256 signatures\n");

    for(i=0; i<NUM_ITER; ++i)
    {
        LOG_INFO("uECC_make_key\n");
        if(!uECC_make_key(l_public, l_private))
        {
            printf("uECC_make_key() failed\n");
            continue;
        }
        watchdog_periodic();
        print_hex(l_public, uECC_BYTES * 2);
        print_hex(l_private, uECC_BYTES);
        memcpy(l_hash, l_public, uECC_BYTES);

        LOG_INFO("uECC_sign\n");
        uint32_t start = clock_time();
        if(!uECC_sign(l_private, l_hash, l_sig))
        {
            printf("uECC_sign() failed\n");
            continue;
        }
        uint32_t time = clock_time() - start;
        watchdog_periodic();

        if (time < min) { min = time; }
        if (time > max) { max = time; }
        accum += time;

        LOG_INFO("uECC_verify\n");
        if(!uECC_verify(l_public, l_hash, l_sig))
        {
            printf("uECC_verify() failed\n");
        }
        watchdog_periodic();
    }
    int avg = accum / NUM_ITER;
    printf("\nSign results (ms): avg=%d min=%d max=%d\n", 
        (avg * 1000) / CLOCK_SECOND,
        (min * 1000) / CLOCK_SECOND,
        (max * 1000) / CLOCK_SECOND);

}
