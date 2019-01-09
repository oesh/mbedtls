/**
 * \file common.h
 *
 * \brief Common functions and macros used by MPS
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_MPS_COMMON_H
#define MBEDTLS_MPS_COMMON_H

#include <stdint.h>

#define MBEDTLS_MPS_MODE_STREAM   0 /* MBEDTLS_SSL_TRANSPORT_STREAM   */
#define MBEDTLS_MPS_MODE_DATAGRAM 1 /* MBEDTLS_SSL_TRANSPORT_DATAGRAM */

/**
 * \name SECTION:       Common types
 *
 * Various common types used throughout MPS.
 * \{
 */

/*! The enumeration of record content types recognized by MPS.
 *
 * \note     Not all of these are visible on the MPS boundary. For example,
 *           ACK messages are handled by MPS internally and are never signalled
 *           to the user.
 *
 * \note     The values are aligned to the ContentType field in [D]TLS records.
 */

typedef uint8_t mbedtls_mps_msg_type_t;

/*! This is a placeholder to indicate that no record is
 *  currently open for reading or writing. */
#define MBEDTLS_MPS_MSG_NONE  ( (mbedtls_mps_msg_type_t) 0 )
/*! This represents Application data messages. */
#define MBEDTLS_MPS_MSG_APP   ( (mbedtls_mps_msg_type_t) 23 )
/*! This represents Handshake messages. */
#define MBEDTLS_MPS_MSG_HS    ( (mbedtls_mps_msg_type_t) 22 )
/*!< This represents Alert messages. */
#define MBEDTLS_MPS_MSG_ALERT ( (mbedtls_mps_msg_type_t) 21 )
/*!< This represents ChangeCipherSpec messages. */
#define MBEDTLS_MPS_MSG_CCS   ( (mbedtls_mps_msg_type_t) 20 )
/*!< This represents ACK messages (used in DTLS 1.3 only). */
#define MBEDTLS_MPS_MSG_ACK   ( (mbedtls_mps_msg_type_t) 25 )

#define MBEDTLS_MPS_MSG_MAX ( (mbedtls_mps_msg_type_t) 31 )

/* TODO: Document */
typedef uint8_t mbedtls_mps_stored_hs_type;
typedef uint_fast8_t mbedtls_mps_hs_type;

/** \brief The type of epoch IDs. */
typedef int8_t mbedtls_mps_epoch_id;
/*! The first unusable unusable epoch ID. */
#define MBEDTLS_MPS_EPOCH_MAX ( ( mbedtls_mps_epoch_id ) 100 /* 0x7FFF */ )
/*! An identifier for the invalid epoch. */
#define MBEDTLS_MPS_EPOCH_NONE ( (mbedtls_mps_epoch_id) -1 )

/** \brief   The type of handshake sequence numbers used in MPS structures.
 *
 *           By the DTLS 1.2 standard (RFC 6347), handshake sequence numbers
 *           are 16-bit, so for full compliance one needs to use a type of
 *           width at least 16 bits here.
 *
 *           The reason to pick a value as small as possible here is
 *           to reduce the size of MPS structures.
 *
 * \warning  Care has to be taken when using a narrower type
 *           than ::mbedtls_mps_stored_hs_seq_nr_t here because of
 *           potential truncation during conversion.
 */
typedef uint8_t mbedtls_mps_stored_hs_seq_nr_t;
#define MBEDTLS_MPS_HS_SEQ_MAX ( (mbedtls_mps_stored_hs_seq_nr_t) -1 )

/** \brief   The type of handshake sequence numbers used
 *           in the implementation.
 *
 *           This must be at least as wide as
 *           ::mbedtls_mps_stored_hs_seq_nr_t but may be chosen
 *           to be strictly larger if more suitable for the
 *           target architecture.
 */
typedef uint_fast8_t mbedtls_mps_hs_seq_nr_t;

/** \brief   The type of buffer sizes and offsets used in MPS structures.
 *
 *           This is an unsigned integer type that should be large enough to
 *           hold the length of any buffer resp. message processed by MPS.
 *
 *           The reason to pick a value as small as possible here is
 *           to reduce the size of MPS structures.
 *
 * \warning  Care has to be taken when using a narrower type
 *           than ::mbedtls_mps_size_t here because of
 *           potential truncation during conversion.
 *
 */
typedef uint16_t mbedtls_mps_stored_size_t;
typedef int16_t mbedtls_mps_stored_opt_size_t;
#define MBEDTLS_MPS_SIZE_MAX ( (mbedtls_mps_stored_size_t) -1 )
#define MBEDTLS_MPS_SIZE_UNKNOWN ( (mbedtls_mps_stored_opt_size_t) -1 )

#define MBEDTLS_MPS_MAX_HS_LENGTH 1000

/* \brief The type of buffer sizes and offsets used in the MPS API
 *        and implementation.
 *
 *        This must be at least as wide as ::mbedtls_stored_size_t but
 *        may be chosen to be strictly larger if more suitable for the
 *        target architecture.
 *
 *        For example, in a test build for ARM Thumb, using uint_fast16_t
 *        instead of uint16_t reduced the code size from 1060 Byte to 962 Byte,
 *        so almost 10%.
 */
typedef uint_fast16_t mbedtls_mps_size_t;

#if (mbedtls_mps_size_t) -1 > (mbedtls_mps_stored_size_t) -1
#error "Misconfiguration of mbedtls_mps_size_t and mbedtls_mps_stored_size_t."
#endif

/* \} SECTION: Common types */

/**
 * \name SECTION:       Parsing and writing macros
 *
 * Macros to be used for parsing various types of fiellds.
 * \{
 */

#define MPS_READ_UINT8_LE( src, dst )                            \
    do                                                           \
    {                                                            \
        *( dst ) = ( (uint8_t*) ( src ) )[0];                    \
    } while( 0 )

#define MPS_WRITE_UINT8_LE( src, dst )                           \
    do                                                           \
    {                                                            \
        *( dst ) = ( (uint8_t*) ( src ) )[0];                    \
    } while( 0 )

#define MPS_READ_UINT16_LE( src, dst )                           \
    do                                                           \
    {                                                            \
        *( dst ) =                                               \
            ( ( (uint16_t) ( (uint8_t*) ( src ) )[0] ) << 8 ) +  \
            ( ( (uint16_t) ( (uint8_t*) ( src ) )[1] ) << 0 );   \
    } while( 0 )

#define MPS_WRITE_UINT16_LE( src, dst )                          \
    do                                                           \
    {                                                            \
        *( (uint8_t*) ( dst ) + 0 ) = ( *( src ) >> 8 ) & 0xFF;  \
        *( (uint8_t*) ( dst ) + 1 ) = ( *( src ) >> 0 ) & 0xFF;  \
    } while( 0 )


#define MPS_WRITE_UINT24_LE( dst, src )                          \
    do                                                           \
    {                                                            \
        *( (uint8_t*) ( dst ) + 0 ) = ( *( src ) >> 16 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 1 ) = ( *( src ) >>  8 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 2 ) = ( *( src ) >>  0 ) & 0xFF; \
    } while( 0 )

#define MPS_READ_UINT24_LE( dst, src )                           \
    do                                                           \
    {                                                            \
        *(dst) =                                                 \
            ( ( (uint32_t) ( (uint8_t*) ( src ) )[0] ) << 16 ) + \
            ( ( (uint32_t) ( (uint8_t*) ( src ) )[1] ) <<  8 ) + \
            ( ( (uint32_t) ( (uint8_t*) ( src ) )[2] ) <<  0 );  \
    } while( 0 )

#define MPS_WRITE_UINT32_LE( dst, src )                          \
    do                                                           \
    {                                                            \
        *( (uint8_t*) ( dst ) + 2 ) = ( *( src ) >> 24 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 3 ) = ( *( src ) >> 16 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 4 ) = ( *( src ) >>  8 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 5 ) = ( *( src ) >>  0 ) & 0xFF; \
    } while( 0 )

#define MPS_READ_UINT32_LE( dst, src )                           \
    do                                                           \
    {                                                            \
        *( dst ) =                                               \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[2] ) << 24 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[3] ) << 16 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[4] ) <<  8 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[5] ) <<  0 );  \
    } while( 0 )

#define MPS_WRITE_UINT48_LE( src, dst )                          \
    do                                                           \
    {                                                            \
        *( (uint8_t*) ( dst ) + 0 ) = ( *( src ) >> 40 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 1 ) = ( *( src ) >> 32 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 2 ) = ( *( src ) >> 24 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 3 ) = ( *( src ) >> 16 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 4 ) = ( *( src ) >>  8 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 5 ) = ( *( src ) >>  0 ) & 0xFF; \
    } while( 0 )

#define MPS_READ_UINT48_LE( src, dst )                           \
    do                                                           \
    {                                                            \
        *( dst ) =                                               \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[0] ) << 40 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[1] ) << 32 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[2] ) << 24 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[3] ) << 16 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[4] ) <<  8 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[5] ) <<  0 );  \
    } while( 0 )

/* \} name SECTION: Parsing and writing macros */

#endif /* MBEDTLS_MPS_COMMON_H */
