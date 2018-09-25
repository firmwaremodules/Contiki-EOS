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
 *         A very simple Contiki application driving EOS functions
 * \author
 *         Evan Ross <contact@firmwaremodules.com>
 */

#include "contiki.h"
#include "dev/watchdog.h"
#include "sys/clock.h"

#include <stdio.h> /* For printf() */
#include <string.h>

#include "ecdsa-engines/hw/ecdsa-cc26x2-adapter.h"
#include "ecdsa-engines/sw/ecdsa-uecc-adapter.h"


void test_ecdsa();
void test_cc26x2_nistp256();

/*---------------------------------------------------------------------------*/
PROCESS(eos_process, "eos process");
AUTOSTART_PROCESSES(&eos_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(eos_process, ev, data)
{
  static struct etimer timer;

  PROCESS_BEGIN();

  test_ecdsa();
  //test_cc26x2_nistp256();

  etimer_set(&timer, CLOCK_SECOND * 5);

  while(1) {
    printf("Hello, EOS\n");

    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    etimer_reset(&timer);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/

static void print_hex(uint8_t* buf, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void print_sig(uint8_t r[32], uint8_t s[32])
{
    printf("r: 0x"); print_hex(r, 32);
    printf("s: 0x"); print_hex(s, 32);
}


/* same random number to compare algs */
static uint8_t k[32] = {
    0xAE, 0x50, 0xEE, 0xFA, 0x27, 0xB4, 0xDB, 0x14,
    0x9F, 0xE1, 0xFB, 0x04, 0xF2, 0x4B, 0x50, 0x58,
    0x91, 0xE3, 0xAC, 0x4D, 0x2A, 0x5D, 0x43, 0xAA,
    0xCA, 0xC8, 0x7F, 0x79, 0x52, 0x7E, 0x1A, 0x7A };

static int fake_rng(uint8_t *p_dest, unsigned p_size)
{
    memcpy(p_dest, k, p_size);
    return 1;
}

// Works.
void test_cc26x2_nistp256()
{
    // This vector is taken from the NIST ST toolkit examples from ECDSA_Prime.pdf
    uint8_t myPrivateKeyingMaterial[32] = {
        0x96, 0xBF, 0x85, 0x49, 0xC3, 0x79, 0xE4, 0x04,
        0xED, 0xA1, 0x08, 0xA5, 0x51, 0xF8, 0x36, 0x23,
        0x12, 0xD8, 0xD1, 0xB2, 0xA5, 0xFA, 0x57, 0x06,
        0xE2, 0xCC, 0x22, 0x5C, 0xF6, 0xF9, 0x77, 0xC4 };

    uint8_t messageHashSHA256[32] = {
        0xC4, 0xA8, 0xC8, 0x99, 0x28, 0xCF, 0x80, 0xB6,
        0xE4, 0x42, 0xD5, 0xBD, 0x28, 0x4D, 0xE3, 0xFD,
        0x3A, 0x13, 0xD8, 0x65, 0x0C, 0x41, 0x1C, 0x21,
        0x48, 0x95, 0x79, 0x2A, 0xA1, 0x41, 0x1A, 0xA4 };

    uint8_t pmsn[32] = {
        0xAE, 0x50, 0xEE, 0xFA, 0x27, 0xB4, 0xDB, 0x14,
        0x9F, 0xE1, 0xFB, 0x04, 0xF2, 0x4B, 0x50, 0x58,
        0x91, 0xE3, 0xAC, 0x4D, 0x2A, 0x5D, 0x43, 0xAA,
        0xCA, 0xC8, 0x7F, 0x79, 0x52, 0x7E, 0x1A, 0x7A };

    uint8_t r[32] = { 0 };
    uint8_t s[32] = { 0 };

    uint8_t theirPublicKeyingMaterial[64] = {
        0x19, 0x7A, 0xBC, 0x89, 0x08, 0xCD, 0x01, 0x82,
        0xA3, 0xA2, 0x9E, 0x1E, 0xAD, 0xA0, 0xB3, 0x62,
        0x1C, 0xBA, 0x98, 0x47, 0x73, 0x8C, 0xDC, 0xF1,
        0xD3, 0xBA, 0x94, 0xFE, 0xFD, 0x8A, 0xE0, 0xB7,
        0x09, 0x5E, 0xCC, 0x06, 0xC6, 0xBB, 0x63, 0xB5,
        0x61, 0x9E, 0x52, 0x43, 0xAE, 0xC7, 0xAD, 0x63,
        0x90, 0x72, 0x28, 0x19, 0xE4, 0x26, 0xB2, 0x4B,
        0x7A, 0xBF, 0x9D, 0x95, 0x47, 0xF7, 0x03, 0x36 };

    // r should be   0x4F, 0x10, 0x46, 0xCA, 0x9A, 0xB6, 0x25, 0x73,
    //               0xF5, 0x3E, 0x0B, 0x1F, 0x6F, 0x31, 0x4C, 0xE4,
    //               0x81, 0x0F, 0x50, 0xB1, 0xF3, 0xD1, 0x65, 0xFF,
    //               0x65, 0x41, 0x7F, 0xD0, 0x76, 0xF5, 0x42, 0x2B
    //
    // s should be   0xF1, 0xFA, 0x63, 0x6B, 0xDB, 0x9B, 0x32, 0x4B,
    //               0x2C, 0x26, 0x9D, 0xE6, 0x6F, 0x88, 0xC1, 0x98,
    //               0x81, 0x2A, 0x50, 0x89, 0x3A, 0x99, 0x3A, 0x3E,
    //               0xCD, 0x92, 0x63, 0x2D, 0x12, 0xC2, 0x42, 0xDC

    watchdog_periodic();
    ecdsa_cc26x2_init(ECDSA_CC26X2_CURVE_NISTP256);
    watchdog_periodic();

    printf("CC26X2 sign...\n");
    if (ecdsa_cc26x2_sign(myPrivateKeyingMaterial, pmsn, messageHashSHA256, r, s) == 0) {
        printf("CC26X2 sign SUCCESS!\n");
    }
    else {
        printf("CC26X2 sign FAILED!\n");
    }
    watchdog_periodic();
    print_sig(r, s);
    printf("CC26X2 verify...\n");
    if (ecdsa_cc26x2_verify(theirPublicKeyingMaterial, messageHashSHA256, r, s) == 0) {
        printf("CC26X2 verify SUCCESS!\n");
    }
    else {
        printf("CC26X2 verify FAILED!\n");
    }
    watchdog_periodic();


}

void test_ecdsa()
{
    uint8_t pub_key[64];
    uint8_t priv_key[32];
    uint8_t hash[32];
    uint8_t r[32];
    uint8_t s[32];

    ecdsa_uecc_init(fake_rng);
    ecdsa_cc26x2_init(ECDSA_CC26X2_CURVE_SECP256K1);

    printf("----- UECC internal test\n");
    ecdsa_uecc_test();

    printf("----- UECC generate keys for test\n");
    ecdsa_uecc_makekey(pub_key, priv_key);
    watchdog_periodic();
    printf("public: 0x");
    print_hex(pub_key, sizeof(pub_key));
    printf("private: 0x");
    print_hex(priv_key, sizeof(priv_key));
    /* use portion of generated pub key as message hash */
    memcpy(hash, pub_key, sizeof(hash));
    printf("hash: 0x");
    print_hex(hash, sizeof(hash));
    printf("k: 0x");
    print_hex(k, sizeof(k));

    printf("----- UECC API test\n");
    memset(r, 0, sizeof(r));
    memset(s, 0, sizeof(s));
    printf("UECC sign...\n");
    if (ecdsa_uecc_sign(priv_key, k, hash, r, s) == 0) {
        printf("UECC sign SUCCESS!\n");
    } else{
        printf("UECC sign FAILED!\n");
    }
    watchdog_periodic();
    print_sig(r, s);
    printf("UECC verify...\n");
    if (ecdsa_uecc_verify(pub_key, hash, r, s) == 0) {
        printf("UECC verify SUCCESS!\n");
    }
    else {
        printf("UECC verify FAILED!\n");
    }
    watchdog_periodic();

    printf("----- CC26X2 API test\n");
    memset(r, 0, sizeof(r));
    memset(s, 0, sizeof(s));
    printf("CC26X2 sign...\n");
    if (ecdsa_cc26x2_sign(priv_key, k, hash, r, s) == 0) {
        printf("CC26X2 sign SUCCESS!\n");
    }
    else {
        printf("CC26X2 sign FAILED!\n");
    }
    watchdog_periodic();
    print_sig(r, s);
    printf("CC26X2 verify...\n");
    if (ecdsa_cc26x2_verify(pub_key, hash, r, s) == 0) {
        printf("CC26X2 verify SUCCESS!\n");
    }
    else {
        printf("CC26X2 verify FAILED!\n");
    }
    watchdog_periodic();

    printf("----- UECC SIGN, CC26X2 VERIFY API test\n");
    memset(r, 0, sizeof(r));
    memset(s, 0, sizeof(s));
    printf("UECC sign...\n");
    if (ecdsa_uecc_sign(priv_key, k, hash, r, s) == 0) {
        printf("UECC sign SUCCESS!\n");
    }
    else {
        printf("UECC sign FAILED!\n");
    }
    watchdog_periodic();
    print_sig(r, s);
    printf("CC26X2 verify...\n");
    if (ecdsa_cc26x2_verify(pub_key, hash, r, s) == 0) {
        printf("CC26X2 verify SUCCESS!\n");
    }
    else {
        printf("CC26X2 verify FAILED!\n");
    }
    watchdog_periodic();


    printf("----- CC26X2 SIGN, UECC VERIFY API test\n");
    memset(r, 0, sizeof(r));
    memset(s, 0, sizeof(s));
    printf("CC26X2 sign...\n");
    if (ecdsa_cc26x2_sign(priv_key, k, hash, r, s) == 0) {
        printf("CC26X2 sign SUCCESS!\n");
    }
    else {
        printf("CC26X2 sign FAILED!\n");
    }
    watchdog_periodic();
    print_sig(r, s);
    printf("UECC verify...\n");
    if (ecdsa_uecc_verify(pub_key, hash, r, s) == 0) {
        printf("UECC verify SUCCESS!\n");
    }
    else {
        printf("UECC verify FAILED!\n");
    }
    watchdog_periodic();

}