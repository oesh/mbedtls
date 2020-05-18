# Outline of MPS-based QUIC integration 

# Overview 

QUIC is a new L4 transport protocol, which uses UDP as L3 layer substrate.
Unlike TCP, QUIC is a cryptographic protocol (TBD explain what this entails).

Currently, QUIC uses TLS v1.3 handshake to establish connections.

This document contains an outline of modifications to MPS-based `mbedTLS` required
to support QUIC.

QUIC support requires changes on multiple layers:

1. The input/output model is different, since QUIC interacts with TLS stack
   using east-west model, vs. north-south model that TCP is using.
2. The confidentiality model is different. QUIC's unit of data protection is a
   "frame", vs. "record" that is used by TLS when working with TCP. QUIC
   transport is responsible for protecting each frame using AEAD method. The
   transport delegates the AEAD implementation to an external library.

# High level design

Instead of implementing a complete QUIC transport stack, this design assumes an
independent component that implements the transport. 

The underlying UDP socket is assumed to be owned by the above transport
component. At the moment of writing, we are using ngtcp2 as the transport
implementation, but the design is not limited to any particular implementation. 

In a similar vein, this design assumes additional independent component that
provices the necessary cryptographic primitives.
                                                
```                                            
    +-----------+                 +-----------+
    |   QUIC    |    Handshake    | TLS stack |
    | transport |--------+------->|           |
    +-----------+     Pro|ocol    +-----------+
          |              |              |      
         UDP             |              |      
      Transport          |              |      
          |              |   Crypto     |      
          |              | Primitives   |      
          |              |              |      
          v              |              v      
    +-----------+        |        +-----------+
    | Operating |        |        |  Crypto   |
    |  System   |        +------->|  Library  |
    +-----------+                 +-----------+
```                                            
Fig. 1 - Component overview.


## Passing data between the QUIC transport and the TLS stack

QUIC carries the handshake data in CRYPTO frames. Except for the first message
(ClientHello/ServerHello), the handshake message boundaries are not guaranteed
to align with the CRYPTO frame boundaries.


The TLS stack informs the QUIC transport when a handshake message is available.

```
   +-----------+                              
   |    App    |                              
   +-----------+                              
         ^                                    
         |                                    
     L4 streams                                
         |                                    
         v                                    
   +-----------+               +-----------+
   |   QUIC    |   Handshake   | TLS stack |
   | transport |<------------->|           |
   +-----------+   messages    +-----------+
         ^                                    
         |                                    
     Packets (*)                              
         |                                    
         v                                    
   +-----------+                              
   |    UDP    |                              
   +-----------+

```
Fig. 2 - Data Flow diagram.


## Key management 

TODO:

1. Key discardment.
2. Key managed by transport.

# Integrating the Handshake Protocol

TODO:

TODO 1. Passing messages between QUIC transport and TLS handshake stack 
TODO 2. Using MPS Layer 2  for passing messages 
TODO 3. Multiple encryption layers

4. Interface to QUIC transport

4.1. Initalization 
TODO:
TODO 4.1.1. Registering the `quic_input` callbacks.
TODO 4.1.2. Providing the client transport parameters.

4.2. Passing the handshake data from the QUIC transport to the TLS stack.


```
    +-------------------+                  +-------------------+      
    |       QUIC        |                  |      MPS L2       |      
    |     transport     |                  |                   |      
    +-------------------+                  +-------------------+      
              |                                      |                
              |                                      |                
     mbedtls_quic_provide_data      l2_in_fetch_protected_record_quic 
              |                                      |                
              | +---------------------------+        |                
              +>|    QUIC input subsytem    |<-------+                
                +---------------------------+                         
                              ^                                       
                              v                                       
            +-----------------------------------+                     
            |          TLS record data          |                     
            +-----------------------------------+
```

Fig 3. - outline of the data flow


1. When the QUIC transport receives CRYPTO data, it passes the contents to
   `mbedTLS` by invoking `mbedtls_quic_provide_data`. The incoming data 
   is appended to an internal input queue that corresponds to the current epoch.

2. When the TLS state machine is wishing to consume the handshake data,
   it invokes the `l2_in_fetch_protected_record_quic` routine, which in turn
   attempts to consume a handshake message from the QUIC input subsystem, 
   by invoking `mbedtls_quic_consume_data`. 

Notes:
1. The UDP datagrams that carry the QUIC packets do not have a guaranteed
   order of arrival. Reassembling the datagrams into a contigous stream of data
   is the responsibility of the QUIC transport.
2. The boundaries of the TLS handshake messages may not be aligned with the 
   boundaries of the QUIC packets, except for the Initial packets. 
   The segmentation of the QUIC packets into disjoint TLS handshake messages is
   the responsibility of the `mbedTLS` integration layer.


4.2.1. Open questions:

4.2.1.1. Should the public API allow providing out-of-order data? If so, the
   semantics of the out-of-order data have to be clearly specified.

```
/**
 * \brief Send handshake data to mbedtls.
 *
 * This is the top level `provide_data` function. It dispatches
 * the incoming data to the appropriate queue, and invokes
 * `quic_input_provide_data` to do the heavy lifting.
 *
 * \param ssl SSL context.
 * \param level encryption level.
 * \param data handshake data.
 * \param len data length.
 */
int mbedtls_quic_input_provide_data(
    mbedtls_ssl_context      *ssl,
    mbedtls_ssl_crypto_level  level,
    const uint8_t            *data,
    size_t                    len);
```

4.3. Passing the handshake data from the TLS stack to the QUIC transport.

When `mbedTLS` has the next handshake message to send, it uses the
`quic_method->add_handshake_data` callback.

TODO 5. Interface to MPS
TODO 5.1. Suggested additions to the MPS message structure
TODO 5.2. Message-based I/O vs. byte-based I/O.
TODO 6. Suggested implementation.


# The Handshake State Machine

TODO:
1. Eliminated state - End of Early Data.
2. Passing alerts.

# Higher level integration - cipher suites 
