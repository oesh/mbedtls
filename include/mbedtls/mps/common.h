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

/**
 * \name SECTION:       MPS Configuration
 *
 * \{
 */

/*! This flag controls whether the MPS-internal components
 *  (reader, writer, Layer 1-3) perform validation of the
 *  expected abstract state at the entry of API calls.
 *
 *  Context: All MPS API functions impose assumptions/preconditions on the
 *  context on which they operate. For example, every structure has a notion of
 *  state integrity which is established by `xxx_init()` and preserved by any
 *  calls to the MPS API which satisfy their preconditions and either succeed,
 *  or fail with an error code which is explicitly documented to not corrupt
 *  structure integrity (such as #MPS_ERR_WANT_READ and #MPS_ERR_WANT_WRITE);
 *  apart from `xxx_init()` any function assumes state integrity as a
 *  precondition (but usually more). If any of the preconditions is violated,
 *  the function's behavior is entirely undefined.
 *  In addition to state integrity, all MPS structures have a more refined
 *  notion of abstract state that the API operates on. For example, all layers
 *  have a notion of 'abtract read state' which indicates if incoming data has
 *  been passed to the user, e.g. through mps_l2_read_start() for Layer 2
 *  or mps_l3_read() in Layer 3. After such a call, it doesn't make sense to
 *  call these reading functions again until the incoming data has been
 *  explicitly 'consumed', e.g. through mps_l2_read_consume() for Layer 2 or
 *  mps_l3_read_consume() on Layer 3. However, even if it doesn't make sense,
 *  it's a design choice whether the API should fail gracefully on such
 *  non-sensical calls or not, and that's what this option is about:
 *
 *  This option determines whether the expected abstract state
 *  is part of the API preconditions or not. If it is, the function's
 *  behavior is undefined if the abstract state is not as expected.
 *  If it is set, API is required to fail gracefully with error
 *  #MPS_ERR_UNEXPECTED_OPERATION, and without changing the abstract
 *  state of the input context, if the abstract state is unexpected but
 *  all other preconditions are satisfied.
 *
 *  For example: Enabling this makes mps_l2_read_done() fail if
 *  no incoming record is currently open; disabling this would
 *  lead to undefined behavior in this case.
 *
 *  Comment this to remove state validation.
 */
//#define MBEDTLS_MPS_STATE_VALIDATION

/*! This flag enables/disables assertions on the internal state of MPS.
 *
 *  Assertions are sanity checks that should never trigger when MPS
 *  is used within the bounds of its API and preconditions.
 *
 *  Enabling this increases security by limiting the scope of
 *  potential bugs, but comes at the cost of increased code size.
 *
 *  At the time of writing (Jan '19), assertions increase
 *  the code size by ~160 bytes.
 *
 *  Note: So far, there is no guiding principle as to what
 *  expected conditions merit an assertion, and which don't.
 *
 *  Comment this to disable assertions.
 */
#define MBEDTLS_MPS_ASSERT

/*! This flag determines whether MPS should perform sanity
 *  checks on the data returned by the record protection API.
 *
 *  MPS Layer 2 doesn't control the actual record protection
 *  but only interfaces with it through the API defined in
 *  transform.h.
 */
//#define MBEDTLS_MPS_TRANSFORM_VALIDATION

/*! This flag controls whether tracing for MPS should be enabled. */
//#define MBEDTLS_MPS_TRACE

/*! This internal macro determines whether all Layers of MPS should
 *  be compiled into a single source file.
 *
 *  Comment to merge all MPS Layers into a single compilation unit,
 *  solely exposing the top-level MPS API.
 */
#define MBEDTLS_MPS_SEPARATE_LAYERS

/** Internal macro sanity check. */
#if defined(MBEDTLS_MPS_TRACE) && \
    !defined(MBEDTLS_MPS_SEPARATE_LAYERS)
#error "Tracing (MBEDTLS_MPS_TRACE) is only possible in multi-unit MPS (MBEDTLS_MPS_SEPARATE_LAYERS)"
#endif /* MBEDTLS_MPS_TRACE && !MBEDTLS_MPS_SEPARATE_LAYERS */

/*! This flag enables support for the TLS protocol.
 *
 *  Uncomment if only DTLS is needed.
 */
//#define MBEDTLS_MPS_PROTO_TLS

/*! This flag enables support for the DTLS protocol.
 *
 *  Uncomment if only TLS is needed.
 */
#define MBEDTLS_MPS_PROTO_DTLS

/** Internal macro sanity check. */
#if !defined(MBEDTLS_MPS_PROTO_TLS) && \
    !defined(MBEDTLS_MPS_PROTO_DTLS)
#error "Either MBEDTLS_MPS_PROTO_TLS or MBEDTLS_MPS_PROTO_DTLS must be set."
#endif /* !MBEDTLS_MPS_PROTO_TLS && !MBEDTLS_MPS_PROTO_DTLS */

#if defined(MBEDTLS_MPS_PROTO_TLS) && \
    defined(MBEDTLS_MPS_PROTO_DTLS)
#define MBEDTLS_MPS_PROTO_BOTH
#endif

/* \} name SECTION: MPS Configuration */

/**
 * \name SECTION:       Common types
 *
 * Various common types used throughout MPS.
 * \{
 */

/*! This determines whether internal computations with values
 *  of small range (such as record content types) should declare the
 *  variables holding those values using the smallest possible type.
 *
 *  This is just to make it easier to investigate the effect
 *  on code size that the choice of integer type has.
 *
 *  Currently, this is disabled by default because allowing
 *  the compiler to use the most natural choice of type for the
 *  target platform appears to lead to slightly smaller code.
 */
//#define MBEDTLS_MPS_INTERNAL_SMALL_TYPES

typedef uint8_t mbedtls_mps_transport_type;
/* MBEDTLS_SSL_TRANSPORT_STREAM   */
#define MBEDTLS_MPS_MODE_STREAM   ((mbedtls_mps_transport_type) 0)
 /* MBEDTLS_SSL_TRANSPORT_DATAGRAM */
#define MBEDTLS_MPS_MODE_DATAGRAM ((mbedtls_mps_transport_type) 1)

#if defined(MBEDTLS_MPS_PROTO_TLS)

#if defined(MBEDTLS_MPS_PROTO_BOTH)
#define MBEDTLS_MPS_IS_TLS( mode )               \
    ( (mode) == MBEDTLS_MPS_MODE_STREAM )
#else
#define MBEDTLS_MPS_IS_TLS( mode ) 1
#endif /* MBEDTLS_MPS_PROTO_BOTH */

#define MBEDTLS_MPS_IF_TLS( mode ) if( MBEDTLS_MPS_IS_TLS( mode ) )
#endif /* MBEDTLS_MPS_PROTO_TLS  */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
#if defined(MBEDTLS_MPS_PROTO_BOTH)
#define MBEDTLS_MPS_IS_DTLS( mode )               \
    ( (mode) == MBEDTLS_MPS_MODE_DATAGRAM )
#define MBEDTLS_MPS_ELSE_IF_DTLS( mode )         \
    else
#else
#define MBEDTLS_MPS_IS_DTLS( mode ) 1
#define MBEDTLS_MPS_ELSE_IF_DTLS( mode )        \
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
#endif /* MBEDTLS_MPS_PROTO_BOTH */

#define MBEDTLS_MPS_IF_DTLS( mode ) if( MBEDTLS_MPS_IS_DTLS( mode ) )
#endif /* MBEDTLS_MPS_PROTO_DTLS  */

/*! The enumeration of record content types recognized by MPS.
 *
 * \note     Not all of these are visible on the MPS boundary. For example,
 *           ACK messages are handled by MPS internally and are never signalled
 *           to the user.
 *
 * \note     The values are aligned to the ContentType field in [D]TLS records.
 */

typedef uint8_t mbedtls_mps_stored_msg_type_t;
#if defined(MBEDTLS_MPS_INTERNAL_SMALL_TYPES)
typedef mbedtls_mps_stored_msg_type_t mbedtls_mps_msg_type_t;
#else
typedef uint_fast8_t mbedtls_mps_msg_type_t;
#endif /* MBEDTLS_MPS_INTERNAL_SMALL_TYPES */

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
#if defined(MBEDTLS_MPS_INTERNAL_SMALL_TYPES)
typedef mbedtls_mps_stored_hs_type mbedtls_mps_hs_type;
#else
typedef uint_fast8_t mbedtls_mps_hs_type;
#endif /* MBEDTLS_MPS_INTERNAL_SMALL_TYPES */


/** \brief The type of epoch IDs. */
typedef int8_t mbedtls_mps_stored_epoch_id;
#if defined(MBEDTLS_MPS_INTERNAL_SMALL_TYPES)
typedef mbedtls_mps_stored_epoch_id mbedtls_mps_epoch_id;
#else
typedef int_fast8_t mbedtls_mps_epoch_id;
#endif /* MBEDTLS_MPS_INTERNAL_SMALL_TYPES */

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
#if defined(MBEDTLS_MPS_INTERNAL_SMALL_TYPES)
typedef mbedtls_mps_stored_hs_seq_nr_t mbedtls_mps_hs_seq_nr_t;
#else
typedef uint_fast8_t mbedtls_mps_hs_seq_nr_t;
#endif /* MBEDTLS_MPS_INTERNAL_SMALL_TYPES */

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
#if defined(MBEDTLS_MPS_INTERNAL_SMALL_TYPES)
typedef mbedtls_mps_stored_opt_size_t mbedtls_mps_size_t;
#else
typedef uint_fast16_t mbedtls_mps_size_t;
#endif /* MBEDTLS_MPS_INTERNAL_SMALL_TYPES */

#if (mbedtls_mps_size_t) -1 > (mbedtls_mps_stored_size_t) -1
#error "Misconfiguration of mbedtls_mps_size_t and mbedtls_mps_stored_size_t."
#endif

#if defined(MBEDTLS_MPS_INTERNAL_SMALL_TYPES)
#undef MBEDTLS_MPS_INTERNAL_SMALL_TYPES
#endif

/* \} SECTION: Common types */

/**
 * \name SECTION:       Parsing and writing macros
 *
 * Macros to be used for parsing various types of fields.
 * \{
 */

#define MPS_READ_UINT8_BE( src, dst )                            \
    do                                                           \
    {                                                            \
        *( dst ) = ( (uint8_t*) ( src ) )[0];                    \
    } while( 0 )

#define MPS_WRITE_UINT8_BE( src, dst )                           \
    do                                                           \
    {                                                            \
        *( dst ) = ( (uint8_t*) ( src ) )[0];                    \
    } while( 0 )

#define MPS_READ_UINT16_BE( src, dst )                           \
    do                                                           \
    {                                                            \
        *( dst ) =                                               \
            ( ( (uint16_t) ( (uint8_t*) ( src ) )[0] ) << 8 ) +  \
            ( ( (uint16_t) ( (uint8_t*) ( src ) )[1] ) << 0 );   \
    } while( 0 )

#define MPS_WRITE_UINT16_BE( src, dst )                          \
    do                                                           \
    {                                                            \
        *( (uint8_t*) ( dst ) + 0 ) = ( *( src ) >> 8 ) & 0xFF;  \
        *( (uint8_t*) ( dst ) + 1 ) = ( *( src ) >> 0 ) & 0xFF;  \
    } while( 0 )


#define MPS_WRITE_UINT24_BE( src, dst )                          \
    do                                                           \
    {                                                            \
        *( (uint8_t*) ( dst ) + 0 ) = ( *( src ) >> 16 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 1 ) = ( *( src ) >>  8 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 2 ) = ( *( src ) >>  0 ) & 0xFF; \
    } while( 0 )

#define MPS_READ_UINT24_BE( src, dst )                           \
    do                                                           \
    {                                                            \
        *(dst) =                                                 \
            ( ( (uint32_t) ( (uint8_t*) ( src ) )[0] ) << 16 ) + \
            ( ( (uint32_t) ( (uint8_t*) ( src ) )[1] ) <<  8 ) + \
            ( ( (uint32_t) ( (uint8_t*) ( src ) )[2] ) <<  0 );  \
    } while( 0 )

#define MPS_WRITE_UINT32_BE( src, dst )                          \
    do                                                           \
    {                                                            \
        *( (uint8_t*) ( dst ) + 0 ) = ( *( src ) >> 24 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 1 ) = ( *( src ) >> 16 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 2 ) = ( *( src ) >>  8 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 3 ) = ( *( src ) >>  0 ) & 0xFF; \
    } while( 0 )

#define MPS_READ_UINT32_BE( src, dst )                           \
    do                                                           \
    {                                                            \
        *( dst ) =                                               \
            ( ( (uint32_t) ( (uint8_t*) ( src ) )[0] ) << 24 ) + \
            ( ( (uint32_t) ( (uint8_t*) ( src ) )[1] ) << 16 ) + \
            ( ( (uint32_t) ( (uint8_t*) ( src ) )[2] ) <<  8 ) + \
            ( ( (uint32_t) ( (uint8_t*) ( src ) )[3] ) <<  0 );  \
    } while( 0 )

#define MPS_WRITE_UINT48_BE( src, dst )                          \
    do                                                           \
    {                                                            \
        *( (uint8_t*) ( dst ) + 0 ) = ( *( src ) >> 40 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 1 ) = ( *( src ) >> 32 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 2 ) = ( *( src ) >> 24 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 3 ) = ( *( src ) >> 16 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 4 ) = ( *( src ) >>  8 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 5 ) = ( *( src ) >>  0 ) & 0xFF; \
    } while( 0 )

#define MPS_READ_UINT48_BE( src, dst )                           \
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
