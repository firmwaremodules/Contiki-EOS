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
*    Implementation definitions for EOS transaction signing engine components.
*
* \author
*    Evan Ross <contact@firmwaremodules.com>
*/

#ifndef __ECDSA_ENGINE_IMPL_H
#define __ECDSA_ENGINE_IMPL_H


/* Get random number k for signing algorithm */
int ecdsa_impl_random(uint8_t k[32]);

/* Get the SHA-256 hash of the message. */
int ecdsa_impl_hash(
    const uint8_t* message,
    uint32_t len,
    uint8_t hash[32]);

/* Compute the ECDSA signature using the secp256k1 curve. */
int ecdsa_impl_sign(
    const uint8_t priv_key[32],
    const uint8_t k[32],
    const uint8_t hash[32],
    uint8_t r[32],
    uint8_t s[32]);

#endif
