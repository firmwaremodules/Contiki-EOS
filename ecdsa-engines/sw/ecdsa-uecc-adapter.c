/*
* Copyright(c) 2018, Firmware Modules Inc.
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met :
*
* *Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
*
* * Redistributions in binary form must reproduce the above copyright notice,
* this list of conditions and the following disclaimer in the documentation
* and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/**
* \file
*    ECDSA transaction signing engine adaptor for the micro ECC software engine.
*    https://github.com/tienfuc/iotivity-democlient-snap/tree/master/extlibs/tinydtls/ecc@bc96b99
*
* \author
*    Evan Ross <contact@firmwaremodules.com>
*/

#include <stdint.h>
#include "ecdsa-engines\ecdsa-engine-impl.h"
#include "ecdsa-uecc-adapter.h"
#include "uecc.h"
#include "dev/watchdog.h"
#include <stdio.h>
#include <string.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "Main"
#define LOG_LEVEL LOG_LEVEL_MAIN

#if 0
static uint64_t g_rand = 88172645463325252ull;
static int fake_rng(uint8_t *p_dest, unsigned p_size)
{
    while (p_size)
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
#endif

/* Initialize engine. */
void ecdsa_uecc_init(rng_func func) 
{
    uECC_set_rng(func);
}

int ecdsa_uecc_makekey(
    uint8_t pub_key[64],
    uint8_t priv_key[32])
{
    int result = uECC_make_key(pub_key, priv_key);
    return (result == 1) ? 0 : -1;
}


/* Get the SHA-256 hash of the message. */
int ecdsa_uecc_hash(
    const uint8_t* message,
    uint32_t len,
    uint8_t hash[32])
{
    return 0;
}

/* Compute the ECDSA signature using the secp256k1 curve. */
int ecdsa_uecc_sign(
    const uint8_t priv_key[32],
    const uint8_t k[32],
    const uint8_t hash[32],
    uint8_t r[32],
    uint8_t s[32])
{
    int result = uECC_sign(priv_key, hash, r);
    return (result == 1) ? 0 : -1;
}

/* Verify the ECDSA signature using the secp256k1 curve. */
int ecdsa_uecc_verify(
    const uint8_t pub_key[64],
    const uint8_t hash[32],
    uint8_t r[32],
    uint8_t s[32])
{
    int result = uECC_verify(pub_key, hash, r);
    return (result == 1) ? 0 : -1;
}

#define NUM_ITER  1

static void print_hex(uint8_t* buf, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

void ecdsa_uecc_test()
{

    uint8_t l_public[uECC_BYTES * 2];
    uint8_t l_private[uECC_BYTES];

    uint8_t l_hash[uECC_BYTES];

    uint8_t l_sig[uECC_BYTES * 2];

    int i;

    int min = 0xFFFFFFFF;
    int max = 0;
    uint64_t accum = 0;

    printf("Micro ECC Configuration:\n");
    printf("  uECC_CURVE=%d\n", uECC_CURVE);
    printf("  uECC_ASM=%d\n", uECC_ASM);
    printf("  uECC_BYTES=%d\n", uECC_BYTES);

    printf("Testing Micro ECC 256 signatures\n");

    for (i = 0; i<NUM_ITER; ++i)
    {
        LOG_INFO("uECC_make_key\n");
        if (!uECC_make_key(l_public, l_private))
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
        if (!uECC_sign(l_private, l_hash, l_sig))
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
        if (!uECC_verify(l_public, l_hash, l_sig))
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