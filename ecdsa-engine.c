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
*    ECDSA transaction signing engine.
*
* \author
*    Evan Ross <contact@firmwaremodules.com>
*/

#include <stdint.h>
#include "ecdsa-engine.h"
#include "ecdsa-engines\ecdsa-engine-impl.h"



void ecdsa_init()
{
    ecdsa_impl_init();
}

int ecdsa_sign(
    const uint8_t priv_key[32],
    const uint8_t* message,
    uint32_t len,
    ecdsa_signature_t* sig)
{
    uint8_t k[32];
    uint8_t hash[32];

    /* Get random number k */
    ecdsa_impl_random(k);

    /* Compute the message hash */
    ecdsa_impl_hash(message, len, hash);

    /* Run the implementation of the ECDSA sign algorithm */
    ecdsa_impl_sign(priv_key, k, hash, sig->r, sig->s);

    return 0;

}


int ecdsa_verify(
    const uint8_t pub_key[64],
    const uint8_t* message,
    uint32_t len,
    ecdsa_signature_t* sig)
{
    uint8_t hash[32];

    /* Compute the message hash */
    ecdsa_impl_hash(message, len, hash);

    /* Run the implementation of the ECDSA verify algorithm */
    ecdsa_impl_verify(pub_key, hash, sig->r, sig->s);

    return 0;

}

