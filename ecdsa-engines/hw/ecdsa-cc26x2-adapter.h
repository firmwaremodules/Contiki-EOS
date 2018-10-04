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
*    Implementation definitions for ECDSA with TI CC26X2 and CC13X2.
*
* \author
*    Evan Ross <contact@firmwaremodules.com>
*/

#ifndef __ECDSA_TICC26X2_ADAPTER_H
#define __ECDSA_TICC26X2_ADAPTER_H

typedef enum
{
    ECDSA_CC26X2_CURVE_SECP256K1,
    ECDSA_CC26X2_CURVE_NISTP256,
} ECDSA_CC26X2_CURVE;

/* */
void ecdsa_cc26x2_init(ECDSA_CC26X2_CURVE curve);

/* Get the SHA-256 hash of the message. */
int ecdsa_cc26x2_hash(
    const uint8_t* message,
    uint32_t len,
    uint8_t hash[32]);

/* Compute the ECDSA signature using the secp256k1 curve. */
int ecdsa_cc26x2_sign(
    const uint8_t priv_key[32],
    const uint8_t k[32],
    const uint8_t hash[32],
    uint8_t r[32],
    uint8_t s[32]);

/* Verify the ECDSA signature using the secp256k1 curve. */
int ecdsa_cc26x2_verify(
    const uint8_t pub_key[64],
    const uint8_t hash[32],
    uint8_t r[32],
    uint8_t s[32]);

void ecdsa_cc26x2_test_sign();
void ecdsa_cc26x2_test_verify();

#endif
