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
*    ECDSA transaction signing engine adaptor for the TI ECDSACC26X2 driver.
*
* \author
*    Evan Ross <contact@firmwaremodules.com>
*/

#include "contiki.h"
#include "dev/watchdog.h"
#include "sys/clock.h"

#include "ecdsa-engines\ecdsa-engine-impl.h"
#include <ti/devices/DeviceFamily.h>
#include DeviceFamily_constructPath(driverlib/pka.h)
#include <ti/drivers/cryptoutils/cryptokey/CryptoKeyPlaintext.h>
#include <ti/drivers/ECDSA.h>
#include "ecdsa-cc26x2-adapter.h"

#define SECP256K1_PARAM_SIZE_BYTES 32

//*****************************************************************************
//
// NIST P256 constants in little endian format. byte[0] is the least
// significant byte and byte[NISTP256_PARAM_SIZE_BYTES - 1] is the most
// significant.
//
//*****************************************************************************
const PKA_EccPoint256 SECP256K1_generator = {
    .x = { .byte = { 0x98, 0x17, 0xF8, 0x16, 0x5B, 0x81, 0xF2, 0x59, 
    0xD9, 0x28, 0xCE, 0x2D, 0xDB, 0xFC, 0x9B, 0x02, 
    0x07, 0x0B, 0x87, 0xCE, 0x95, 0x62, 0xA0, 0x55, 
    0xAC, 0xBB, 0xDC, 0xF9, 0x7E, 0x66, 0xBE, 0x79 } },
    .y = { .byte = { 0xB8, 0xD4, 0x10, 0xFB, 0x8F, 0xD0, 0x47, 0x9C, 
    0x19, 0x54, 0x85, 0xA6, 0x48, 0xB4, 0x17, 0xFD, 
    0xA8, 0x08, 0x11, 0x0E, 0xFC, 0xFB, 0xA4, 0x5D, 
    0x65, 0xC4, 0xA3, 0x26, 0x77, 0xDA, 0x3A, 0x48 } },
};

const PKA_EccParam256 SECP256K1_prime = { 
    .byte = { 0x2F, 0xFC, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } };

const PKA_EccParam256 SECP256K1_a = { 
    .byte = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

const PKA_EccParam256 SECP256K1_b = { 
    .byte = { 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

const PKA_EccParam256 SECP256K1_order = { 
    .byte = { 0x41, 0x41, 0x36, 0xD0, 0x8C, 0x5E, 0xD2, 0xBF,
    0x3B, 0xA0, 0x48, 0xAF, 0xE6, 0xDC, 0xAE, 0xBA, 
    0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } };


const ECCParams_CurveParams ECCParams_SECP256K1 = {
    .curveType = ECCParams_CURVE_TYPE_SHORT_WEIERSTRASS,
    .length = SECP256K1_PARAM_SIZE_BYTES,
    .prime = SECP256K1_prime.byte,
    .order = SECP256K1_order.byte,
    .a = SECP256K1_a.byte,
    .b = SECP256K1_b.byte,
    .generatorX = SECP256K1_generator.x.byte,
    .generatorY = SECP256K1_generator.y.byte
};

static ECDSA_Handle ecdsaHandle;

const ECCParams_CurveParams* p_curve;

void ecdsa_cc26x2_init(ECDSA_CC26X2_CURVE curve)
{
    ECDSA_init();
    // Since we are using default ECDSA_Params, we just pass in NULL for that parameter.
    ecdsaHandle = ECDSA_open(0, NULL);

    switch (curve) {
    default:
    case ECDSA_CC26X2_CURVE_SECP256K1:
        p_curve = &ECCParams_SECP256K1;
        break;
    case ECDSA_CC26X2_CURVE_NISTP256:
        p_curve = &ECCParams_NISTP256;
        break;
    }

}


/* Get the SHA-256 hash of the message. */
int ecdsa_cc26x2_hash(
    const uint8_t* message,
    uint32_t len,
    uint8_t hash[32])
{
    return 0;
}

/* Compute the ECDSA signature using the secp256k1 curve. */
int ecdsa_cc26x2_sign(
    const uint8_t priv_key[32],
    const uint8_t k[32],
    const uint8_t hash[32],
    uint8_t r[32],
    uint8_t s[32])
{

    CryptoKey myPrivateKey;
    CryptoKey pmsnKey;
    int_fast16_t operationResult;
    ECDSA_OperationSign operationSign;

    if (!ecdsaHandle) {
        printf("ECDSA not initialized!");
        return -1;
    }

    // Initialize myPrivateKey
    CryptoKeyPlaintext_initKey(&myPrivateKey, (uint8_t*)priv_key, 32);
    CryptoKeyPlaintext_initKey(&pmsnKey, (uint8_t*)k, 32);

    // Initialize the operation
    ECDSA_OperationSign_init(&operationSign);
    operationSign.curve = p_curve;
    operationSign.myPrivateKey = &myPrivateKey;
    operationSign.pmsn = &pmsnKey;
    operationSign.hash = hash;
    operationSign.r = r;
    operationSign.s = s;

    // Generate the signature
    operationResult = ECDSA_sign(ecdsaHandle, &operationSign);

    return operationResult;
}

/* Verify the ECDSA signature using the secp256k1 curve. */
int ecdsa_cc26x2_verify(
    const uint8_t pub_key[64],
    const uint8_t hash[32],
    uint8_t r[32],
    uint8_t s[32])
{
    CryptoKey theirPublicKey;
    int_fast16_t operationResult;
    ECDSA_OperationVerify operationVerify;

    if (!ecdsaHandle) {
        printf("ECDSA not initialized!");
        return -1;
    }

    // Initialize theirPublicKey
    CryptoKeyPlaintext_initKey(&theirPublicKey, (uint8_t*)pub_key, 64);

    ECDSA_OperationVerify_init(&operationVerify);
    operationVerify.curve = p_curve;
    operationVerify.theirPublicKey = &theirPublicKey;
    operationVerify.hash = hash;
    operationVerify.r = r;
    operationVerify.s = s;

    // Verify the signature
    operationResult = ECDSA_verify(ecdsaHandle, &operationVerify);

    return operationResult;
}

//66d59cd0e3e8877be123612ce5112cd24957db5c02c01c20ff554eb2c9eab8af1d0b6aa5f589e23deea2e459085456136f001cd2aec0111acf61e11ee8ecb419
//0000200000013bbb0000000020003fa40000000000000002e4093df8432a8be5

void ecdsa_cc26x2_test_sign()
{
    printf("test sign...\n");

    watchdog_periodic();
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


    CryptoKey myPrivateKey;
    CryptoKey pmsnKey;



    int_fast16_t operationResult;

    ECDSA_OperationSign operationSign;

    int start = clock_time();

    if (!ecdsaHandle) {
        printf("ECDSA_open FAILED!");
        return;
    }

    // Initialize myPrivateKey
    CryptoKeyPlaintext_initKey(&myPrivateKey, myPrivateKeyingMaterial, sizeof(myPrivateKeyingMaterial));
    CryptoKeyPlaintext_initKey(&pmsnKey, pmsn, sizeof(pmsn));

    // Initialize the operation
    ECDSA_OperationSign_init(&operationSign);
    operationSign.curve = p_curve;
    operationSign.myPrivateKey = &myPrivateKey;
    operationSign.pmsn = &pmsnKey;
    operationSign.hash = messageHashSHA256;
    operationSign.r = r;
    operationSign.s = s;

    int inittime = clock_time() - start;

    start = clock_time();
    // Generate the signature
    operationResult = ECDSA_sign(ecdsaHandle, &operationSign);
    int signtime = clock_time() - start;
    if (operationResult != ECDSA_STATUS_SUCCESS) {
        printf("ECDSA_sign FAILED!\n");
    }
    else {
        printf("ECDSA_sign SUCCESS! init=%d sign=%d\n",
            (inittime * 1000) / CLOCK_SECOND,
            (signtime * 1000) / CLOCK_SECOND);
    }

    ECDSA_close(ecdsaHandle);
    // Send out signature
    // r should be   0x4F, 0x10, 0x46, 0xCA, 0x9A, 0xB6, 0x25, 0x73,
    //               0xF5, 0x3E, 0x0B, 0x1F, 0x6F, 0x31, 0x4C, 0xE4,
    //               0x81, 0x0F, 0x50, 0xB1, 0xF3, 0xD1, 0x65, 0xFF,
    //               0x65, 0x41, 0x7F, 0xD0, 0x76, 0xF5, 0x42, 0x2B
    //
    // s should be   0xF1, 0xFA, 0x63, 0x6B, 0xDB, 0x9B, 0x32, 0x4B,
    //               0x2C, 0x26, 0x9D, 0xE6, 0x6F, 0x88, 0xC1, 0x98,
    //               0x81, 0x2A, 0x50, 0x89, 0x3A, 0x99, 0x3A, 0x3E,
    //               0xCD, 0x92, 0x63, 0x2D, 0x12, 0xC2, 0x42, 0xDC

}




void ecdsa_cc26x2_test_verify()
{

    printf("test verify...\n");
    watchdog_periodic();

    // This vector is taken from the NIST ST toolkit examples from ECDSA_Prime.pdf
    uint8_t theirPublicKeyingMaterial[64] = { 
        0x19, 0x7A, 0xBC, 0x89, 0x08, 0xCD, 0x01, 0x82,
        0xA3, 0xA2, 0x9E, 0x1E, 0xAD, 0xA0, 0xB3, 0x62,
        0x1C, 0xBA, 0x98, 0x47, 0x73, 0x8C, 0xDC, 0xF1,
        0xD3, 0xBA, 0x94, 0xFE, 0xFD, 0x8A, 0xE0, 0xB7,
        0x09, 0x5E, 0xCC, 0x06, 0xC6, 0xBB, 0x63, 0xB5,
        0x61, 0x9E, 0x52, 0x43, 0xAE, 0xC7, 0xAD, 0x63,
        0x90, 0x72, 0x28, 0x19, 0xE4, 0x26, 0xB2, 0x4B,
        0x7A, 0xBF, 0x9D, 0x95, 0x47, 0xF7, 0x03, 0x36 };
    uint8_t messageHashSHA256[32] = { 
        0xC4, 0xA8, 0xC8, 0x99, 0x28, 0xCF, 0x80, 0xB6,
        0xE4, 0x42, 0xD5, 0xBD, 0x28, 0x4D, 0xE3, 0xFD,
        0x3A, 0x13, 0xD8, 0x65, 0x0C, 0x41, 0x1C, 0x21,
        0x48, 0x95, 0x79, 0x2A, 0xA1, 0x41, 0x1A, 0xA4 };
    uint8_t r[32] = { 
        0x4F, 0x10, 0x46, 0xCA, 0x9A, 0xB6, 0x25, 0x73,
        0xF5, 0x3E, 0x0B, 0x1F, 0x6F, 0x31, 0x4C, 0xE4,
        0x81, 0x0F, 0x50, 0xB1, 0xF3, 0xD1, 0x65, 0xFF,
        0x65, 0x41, 0x7F, 0xD0, 0x76, 0xF5, 0x42, 0x2B };
    uint8_t s[32] = { 
        0xF1, 0xFA, 0x63, 0x6B, 0xDB, 0x9B, 0x32, 0x4B,
        0x2C, 0x26, 0x9D, 0xE6, 0x6F, 0x88, 0xC1, 0x98,
        0x81, 0x2A, 0x50, 0x89, 0x3A, 0x99, 0x3A, 0x3E,
        0xCD, 0x92, 0x63, 0x2D, 0x12, 0xC2, 0x42, 0xDC };


    CryptoKey theirPublicKey;

    ECDSA_Handle ecdsaHandle;

    int_fast16_t operationResult;

    ECDSA_OperationVerify operationVerify;

    int start = clock_time();

    // Since we are using default ECDSA_Params, we just pass in NULL for that parameter.
    ecdsaHandle = ECDSA_open(0, NULL);

    if (!ecdsaHandle) {
        printf("ECDSA_open FAILED!");
        return;
    }

    // Initialize theirPublicKey
    CryptoKeyPlaintext_initKey(&theirPublicKey, theirPublicKeyingMaterial, sizeof(theirPublicKeyingMaterial));

    ECDSA_OperationVerify_init(&operationVerify);
    operationVerify.curve = p_curve;
    operationVerify.theirPublicKey = &theirPublicKey;
    operationVerify.hash = messageHashSHA256;
    operationVerify.r = r;
    operationVerify.s = s;

    int inittime = clock_time() - start;

    start = clock_time();

    // Generate the keying material for myPublicKey and store it in myPublicKeyingMaterial
    operationResult = ECDSA_verify(ecdsaHandle, &operationVerify);
    int verifytime = clock_time() - start;

    if (operationResult != ECDSA_STATUS_SUCCESS) {
        printf("ECDSA_verify FAILED!\n");
    }
    else {
        printf("ECDSA_verify SUCCESS! init=%d sign=%d\n",
            (inittime * 1000) / CLOCK_SECOND,
            (verifytime * 1000) / CLOCK_SECOND);
    }

    ECDSA_close(ecdsaHandle);
}



