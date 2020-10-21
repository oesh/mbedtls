# Defragmenting handshake messages based on MPS reader

# Summary

At the momement, TLS handshake fragmentation is not supported. In particular
this limits the max certificate length that mbedTLS client can receive.

## Goals

1. Full backwards compatibility with the mbedTLS 2.16 version, unless the user
   explicitly enables fragmentation support in `config.h`.
2. Minimizing the conceptual changes to the mbedTLS 2.16 codebase.
3. Robustness and simplicity.

## Non-goals

1. Minimal memory footprint when the fragmentation is enabled.

# Detailed description of the problem

TLS handshake messages can exceed the maximal TLS record size. Examples include large certificates.

If the handshake message is fragmented, the handshake header is included in the
TLS record that carries the first fragment. Payload of the TLS records that
carry subsequent fragments starts with a body at some offset.

The simple scenario assumes that the fragmented handshake message starts and
ends at the record boundary:

```
+---------------------------+    +---------------------+
|TLS                        |    |TLS                  |
|hdr | payload              |    |hdr | payload        |
+----+----------------------+    +----+----------------+
     | +------+------------+|         | +------------+ |
     | |HS Hdr|Body Frag 0 ||  ...    | |Body Frag #n| |
     | +------+------------+|         | +------------+ |
     +----------------------+         +----------------+
```

A more realistic scenario includes the possibility that the first fragment is
preceded by data that belongs to a different handshake message , or that the
last fragment is followed by another message

A more realistic scenario drops the assumption. The TLS record that carries the
first fragment can start with "leading data", which belongs to the preceding
handshake message.

Similarly, the TLS record that carries the last fragment can include "trailing
data", which belongs to the following handshake message.

Finally, the fragmented message can be bracketed between the "leading" and
"trailing" data:

```
+--------------------------------------+    +-------------------------------------+
|TLS                                   |    |TLS                                  |
|hdr | payload                         |    |hdr | payload                        |
+----+---------------------------------+    +----+--------------------------------+
     |  +--------+------+------------+ |         | +------------+------+--------+ |
     |  |.. data |HS Hdr|Body Frag 0 | |   ...   | |Body Frag #n|HS Hdr|data ...| |
     |  +--------+------+------------+ |         | +------------+------+--------+ |
     +---------------------------------+         +--------------------------------+
```

# Proposed solution

The suggeseted approach is using `mbedtls_reader` as accumulator for the
handshake messages. All incoming TLS records that contain handshake data are
appended to `ssl->hs_reader`.


## Overview of `mbedtls_ssl_read_record`

When the TLS handshake state machine needs a new handshake message (e.g. when
reading `server_hello`), the corresponding function invokes
`mbedtls_ssl_read_record`. See the detailed description below the diagram:

```
     +---------------+
     |               |
     |               v
     |+----------------------------+
     || consume: if whole message  |
     ||has been read the last time,|<-+
     ||     commit its length.     |  |
     |+----------------------------+  |
     |               |                |
     |               v            record not
     |     +------------------+   available.
     |     | Get TLS record.  |       |
     |     |                  |       |
     |     +------------------+       |
     |               |                |
     |               v                |
     |     +------------------+       |
     |     |  Has whole TLS   |       |
     |     |     record?      |-------+
     |     +------------------+
     |               |
     |          has record.
     |               v
     |  +------------------------+
     |  | Feed the TLS record to |
     |  |     ssl->hs_reader     |
     |  +------------------------+
     |               |
     |               v
     |  +------------------------+
     |  |   Prepare the record   |
     |  +------------------------+
More data            |
  needed             v
     |  +------------------------+
     |  |  Has whole handshake   |
     +--|        message?        |
        +------------------------+
                     |
                     v
        +------------------------+
        | Set `ssl->in_msg` and  |
        |    `ssl->in_hslen`     |
        +------------------------+
```

The `mbedtls_ssl_read_record` function starts by invoking
`ssl_consume_current_message`, which is described in detail below.

At the next step, `mbedtls_ssl_read_record` function checks whether a TLS
record is being consumed (via `ssl_record_is_in_progress`).

If this is not the case, `mbedtls_ssl_read_record` invokes
`ssl_get_next_record` repeatedly to until a full TLS record is available.

Once the TLS record is available, `mbedtls_ssl_read_record` passes the contents
of the record to `ssl->hs_reader`, and invokes
`mbedtls_ssl_prepare_handshake_record` (via `mbedtls_ssl_handle_message_type`).

The latter function checks whether a full handshake message is available, by
attempting to read a handshake header, followed by an attempt to read the
entire body of the handshake message.

If both the header and the body of a handshake message are available,
`mbedtls_ssl_prepare_handshake_record` prepares the `ssl` context for consuming
the next recrod, via:

1. Setting `ssl->in_hslen` to the length of the entire handshake message
   (including the header)
2. Adjusting the `ssl->in_msg` pointer so that it points to the first byte of
   the handshake header.
3. Returning 0, to indicate that the handshake message has been prepared,
   and can be parsed starting from `ssl->in_msg`.

NOTE: Depending on whether `ssl->hs_reader` had to reassemble the message or
not, the `ssl->in_msg` pointer can point to internal memory allocated by the
reader, or to location in `ssl->in_buf`.

Otherwise (either the body or header are not availalbe),
`mbedtls_ssl_prepare_handshake_record` keeps the stack ready for more incoming
data, by:

1. Resetting the `ssl->in_msg` to point to the beginning of `ssl->in_buf`
2. Setting `ssl->in_hslen` to 0
3. Returning `MBEDTLS_ERR_SSL_CONTINUE_PROCESSING`, indicating that more data is required.

Once the `ssl->in_buf` has been set to the beginning of the handshake message,
`mbedtls_ssl_read_record` returns, and the parsing function can access the
handshake data via `ssl->in_msg`.

### Behavior of `ssl_consume_current_message`

The function `ssl_consume_current_message` is invoked by `mbedtls_ssl_read_record` to clean up buffesrs that are no longer in use.  Several possiblities exist:
1. `ssl->hs_reader` is empty.
2. `ssl->hs_reader` contains fragment of the handshake message.
3. `ssl->hs_reader` contains an entire handshake message, possibliy followed by
    data that belongs to the next message.


In the latter (the most generic) case, `ssl->hs_reader` will need to:
1. Invoke `mbedtls_reader_commit` to mark the area that can be reclaimed.
2. Invoke `mbedtls_reader_reclaim` to return the buffers that have been committed.

```
+------------------------------------------------------------------------+
|+------------------------------------------+ +------------------------+ |
||+------+---------------------------------+| |                        | |
||| hdr  |              body               || |    Additional data     | |
||+------+---------------------------------+| |                        | |
|+------------------------------------------+ +------------------------+ |
+------------------------------------------------------------------------+
                                            ^
Can be committed and reclaimed              |    Is still needed
```

`ssl_consume_current_message` is relying on `ssl->in_hslen` to know how much
data can be commited and reclaimed (if any):
- If a whole handshake message has been received in the previous invocation of
  `mbedtls_ssl_read_record`, then the `ssl->in_hslen` will be greater than 0.
- Otherwise, `ssl->in_hslen` will be equal to 0.

Because of that, `ssl_consume_current_message` can pass the value of
`ssl->in_hslen` to `mbedtls_reader_commit`, and invoke
`mbedtls_reader_reclaim`.


