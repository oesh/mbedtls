# Outline of MPS-based QUIC integration 

# Overview 

QUIC is a new L4 transport protocol, which uses UDP as L3 layer substrate.
Unlike TCP, QUIC is a cryptographic protocol (TBD explain what this entails).

Currently, QUIC uses TLS v1.3 handshake to establish connections.

This document contains an outline of modifications to MPS-based MbedTLS required
to support QUIC.

QUIC support requires changes on multiple layers:

1. The input/output model is different, since QUIC interacts with TLS stack
   using east-west model, vs. north-south model that TCP is using.
2. The confidentiality model is different. QUIC's unit of data protection is a
   "frame", vs. "record" that is used by TLS when working with TCP. QUIC
   transport is responsible for protecting each frame using AEAD method. The
   transport delegates the AEAD implementation to an external library.

## Data flow diagram 

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

## Dependency diagram
                                                
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

# Key management 

TODO:

1. Key discardment.
2. Key managed by transport.


# Integrating the Handshake Protocol

TODO:

1. Passing messages between QUIC transport and TLS handshake stack 
2. Using MPS Layer 2  for passing messages 
3. Multiple encryption layers
4. Interface to QUIC transport
4.1 Callback structure
5. Interface to MPS
5.1. Suggested additions to the MPS message structure
5.2. Message-based I/O vs. byte-based I/O.
6. Suggested implementation.


# The Handshake State Machine

TODO:
1. Eliminated state - End of Early Data.
2. Passing alerts.

# Higher level integration - cipher suites 
