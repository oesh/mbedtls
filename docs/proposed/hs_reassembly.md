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

TLS handshake messages can exceed the maximal TLS record size. Examples include
large certificates.

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


## Data structures

```
struct mbedtls_ssl_config {

#if defined(MBEDTLS_SSL_HS_REASSEMBLY)
    size_t hs_reassembly_enabled;
    size_t accumulator_size;
#endif /* MBEDTLS_SSL_HS_REASSEMBLY */
}

void mbedtls_ssl_conf_hs_reassembly_enable( mbedtls_ssl_config *conf, int enable);
void mbedtls_ssl_conf_hs_reassembly_set_max_hs_length( mbedtls_ssl_config *conf, int enable);

struct mbedtls_ssl_context {

...

#if defined(MBEDTLS_SSL_HS_REASSEMBLY)
     /* reassembly section */
     struct {
        size_t enabled;
        struct mbedtls_reader *reader;
        unsigned char *accumulator;
        const unsigned char *reassembled_msg;
     } hs_reassembly;
#endif /* MBEDTLS_SSL_HS_REASSEMBLY */

...

};

```

## Overview of `mbedtls_ssl_read_record`

The TLS handshake state machine invokes `mbedtls_ssl_read_record` when a new
record is needed. When reassembly is enabled, the latter performs the following
sequence:

1. Uses `ssl_consume_current_message` to clean up buffers.

2. If needed, uses `ssl_get_next_record` to more additional TLS record(s).
   This is done in the same fashion as before.

3. Uses `mbedtls_reader_feed` to pass the entire contents of the TLS record to
   the MPS reader.

4. Uses `mbedtls_ssl_prepare_handshake_record` to check whether a complete
   handshake message is available, by:

   a. Attempting to read the header of the handshake message from the MPS reader.
   b. Attempting to read the body of the handshake message.

   If either of the two read attempts fails, this indicates that the handshake
   message is fragmented across several TLS records, and additional data
   is required.

```
                       +-------------------------+
                       |                         |
                       v                         |
           +------------------+                  |
Step 1:    | clean up buffers |<-----+           |
           +------------------+      |           |
                       |         More data       |
                       v         is needed.      |
           +------------------+      |           |
Step 2:    | Get TLS record.  |------+           |
           +------------------+                  |
                       |                         |
            Complete TLS record                  |
                is available.                    |
                       |                         |
                       v                         |
          +------------------------+             |
Step 3:   | Feed the TLS record to |     More TLS records
          |     ssl->hs_reader     |       are needed.
          +------------------------+             |
                       |                         |
                       v                         |
          +-------------------------+            |
Step 4:   |   Prepare the handshake |------------+
          |         message         |
          +-------------------------+
                       |
           Complete handshake message
                  is available
                       |
                       v
          /------------------------\
          | Return to the caller   |
          \------------------------/
```

See "Detailed description of hte reassembly" below for the discussion on how
the different edge cases are handled.


## Accessing the reassembled messages

Since the reassembled messages will not fit into `ssl->in_buf` (which is sized
for the TLS record, and not for a handshake message), the TLS handshake state machine will have to read the reassembled buffers from the accumulator memory.

To make this less error prone, this design suggests introducing a helper function, `mbedtls_ssl_hs_reassembled_buf_ptr`, which will return the correct pointer, e.g.


```
static inline const unsigned char* mbedtls_ssl_hs_reassembled_buf_ptr(
    const mbedtls_ssl_context *ssl ) {
    if ( ssl->hs_reader ) {
        return ssl->reassembled_hs_buf;
    } else {
        return ssl->in_buf;
    }
}
```

The parsing functions will use this function to get a pointer to the handshake
message after invoking `mbedtls_ssl_read_record`.

# Detailed design

### Detailed description of the reassembly

A few typical cases are described below. The cleanup procedure (Step 1) is
described the last, since it is easier to understand this way.

#### Single handshake message in a single TLS record

```
+-----------------------------+
|TLS                          |
|hdr | payload                |
+----+------------------------+
     |  +------+------------+ |
     |  |HS Hdr|HS body     | |
     |  +------+------------+ |
     +------------------------+
```

1. At step 2, the entire TLS record is read (potentially in several iterations
   of the reading loop).
2. At step 3, the contents of the TLS record are transferred to the MPS reader.
   The state of the MPS reader at this point is:

```
ssl:
  +- in_msg + in_msglen --------+
  +- in_msg +                   |
  +- in_buf |                   |
     v      v                   v
     +------------------------------------------+
     |TLS hdr|HS hdr|HS body                    |
     +------------------------------------------+
     ^                          ^
     +-----------+              |
                 |              |
ssl->hs_reader:  |              |
  +-- frag ------+              |
  +-- { frag + frag_len }  -----+
  |
  +-- { acc + acc_avail } ------+
  +-- end    -+                 |
  +-- commit -+                 |
  |           v                 v
  +- acc --> +------------------------------------------------+
             |HS hdr|HS body                                  |
             +------------------------------------------------+
```
Notes:
    a. The `ssl->hs_reader->end` is pointing to the beginning of the buffer,
       because no attempts to read the data were made.

    b. The `ssl->hs_reader->commit` is pointing to the beginning of the buffer,
       because the (absent) reads were not committed.

3. At step 4, since the TLS record contains both the header and the body of the
   handshake message, `ssl_prepare_handshake_record` succeeds.

   The state of the MPS reader at this point is:

```
ssl:
  +- in_msg + in_msglen --------+
  +- in_msg +                   |
  +- in_buf |                   |
     v      v                   v
     +------------------------------------------+
     |TLS hdr|HS hdr|HS body                    |
     +------------------------------------------+
     ^                          ^
     +-----------+              |
                 |              |
ssl->hs_reader:  |              |
  +-- frag ------+              |
  +-- { frag + frag_len }  -----+
  |
  +-- { acc + acc_avail } ------+
  +-- end    -------------------+
  +-- commit +                  |
  |          v                  v
  +- acc --> +------------------------------------------------+
             |HS hdr|HS body                                  |
             +------------------------------------------------+
```
Notes:
    a. The `ssl->hs_reader->end` has moved to the offset of the
       last chunk that has been requested by `ssl_prepare_handshake_record`,
       i.e. the end of the handshake message.

    b. The `ssl->hs_reader->commit` is still pointing to the beginning
       of the buffer, because the (absent) reads were not committed.

4. The handshake message can be processed at this point.

5. At the Step 1 of the subsequent read, `ssl_consume_current_message` uses
   `mbedtls_reader_commit` to tell the MPS reader that all the data that have
    been reaad can be reclaimed, followed by a call to `mbedtls_reader_reclaim`,
    which releases the buffers.

    After the call to `mbedtls_reader_commit`, the state of the reader becomes:

```
ssl:
  +- in_msg + in_msglen --------+
  +- in_msg +                   |
  +- in_buf |                   |
     v      v                   v
     +------------------------------------------+
     |TLS hdr|HS hdr|HS body                    |
     +------------------------------------------+
     ^                          ^
     +-----------+              |
                 |              |
ssl->hs_reader:  |              |
  +-- frag ------+              |
  +-- { frag + frag_len }  -----+
  |
  +-- { acc + acc_avail } +
  +-- end    +            |
  +-- commit + -----------+
  |          v
  +- acc --> +------------------------------------------------+
             |HS hdr|HS body                                  |
             +------------------------------------------------+
```
    After the call to `mbedtls_reader_reclaim`, since the entire span of
    `hs_reader->acc_avail` has been committed, it is being reclaimed,
     leading to the following state:

#### Single handshake message in several TLS records, no trailing data.

```
+---------------------------+    +---------------------+
|TLS                        |    |TLS                  |
|hdr | payload              |    |hdr | payload        |
+----+----------------------+    +----+----------------+
     | +------+------------+|         | +------------+ |
     | |HS Hdr|Body Frag #0||  ...    | |Body Frag #n| |
     | +------+------------+|         | +------------+ |
     +----------------------+         +----------------+
```

Depending on whether both TLS records are available for reading,
this scenario can require two subsequent calls to `mbedtls_ssl_read_record`.
The explanation below assumes that this is the case, for clarity.

1. First invocation of `mbedtls_ssl_read_record`:
    a. At step 2, the entire first TLS record is read (potentially in several
       iterations of the reading loop).

    b. At step 3, the contents of the TLS record are transferred to the MPS
       reader.

    c. At step 4, `ssl_prepare_handshake_record` successfully reads the header
       of the handshake message, but fails to read the mesage body.

       The state of the MPS reader at this point is:

```
ssl:
  +- in_msg + in_msglen --------+
  +- in_msg +                   |
  +- in_buf |                   |
     v      v                   v
     +------------------------------------------+
     |TLS hdr|HS hdr|Body frag #0               |
     +------------------------------------------+
     ^                          ^
     +-----------+              |
                 |              |
ssl->hs_reader:  |              |
  +-- frag ------+              |
  +-- { frag + frag_len }  -----+
  |
  +-- end    -----------------------------------------+
  +-- { acc + acc_avail } ------+                     |
  +-- commit +                  |                     |
  |          v                  v                     v
  +- acc --> +------------------------------------------------+
             |HS hdr|Body frag #0                             |
             +------------------------------------------------+
```

Notes:
    a. `ssl->hs_reader->end` points past `ssl->hs_reader->{acc + acc_avail}`,
        because `ssl_prepare_handshake_record` attempted to read
        the entire span of the handshake message, which is not available yet.

2. Second invocation of `mbedtls_ssl_read_record`:

    a. Back to Step 2, the second TLS record is read in entirety.

    b. At Step 3, the contents of the second TLS record are passed to the MPS
       reader, which accumulates the data.

       The state of the MPS reader at this point is:

```
ssl:
  +- in_msg + in_msglen --------+
  +- in_msg +                   |
  +- in_buf |                   |
     v      v                   v
     +------------------------------------------+
     |TLS hdr|Body frag #1                      |
     +------------------------------------------+
     ^                          ^
     +-----------+              |
                 |              |
ssl->hs_reader:  |              |
  +-- frag ------+              |
  +-- { frag + frag_len }  -----+
  |
  +-- end    -----------------------------------------+
  +-- { acc + acc_avail } ----------------------------+
  +-- commit -+                                       |
  |           v                                       v
  +- acc --> +------------------------------------------------+
             |HS hdr|Body frag #0: Body frag #1               |
             +------------------------------------------------+
```

    c. At step 4, `ssl_prepare_handshake_record` successfully reads both the
       header and the body of the handshake message. Because the reader
       contains enough data to satisfy the read, it succeeds.


3. At the Step 1 of the subsequent read, `ssl_consume_current_message` uses
   `mbedtls_reader_commit` and `mbedtls_reader_reclaim` to release the buffers.
    Because there is no trailing data, the accumulator buffer is cleared,
    similarly to the previous case.

#### Message boundary in the TLS record

This case describes the situation where a single TLS message contains both the end of message `k`, and the beginning of message `k+1`:

```
+---------------------------------------+
|TLS                                    |
|hdr | payload                          |
+----+----------------------------------+
     |  +------+-----+------+--------+  |
     |  |HS Hdr|Body |HS Hdr|data ...|  |
     |  +------+-----+------+--------+  |
     +----------------------------------+
                     ^
                     |
                     +--- message boundary
```

The difference is addressed by the semantics of the
`mbedlts_reader_commit`/`mbedtls_reader_reclaim`, as illustrated below:


1. When the message `k` has been read, the reader is in the following state:

```
ssl:
  +- in_msg + in_msglen -----------------+
  +- in_msg +                            |
  +- in_buf |                            |
     v      v                            v
     +------------------------------------------+
     |TLS hdr| ... msg k | msg k + 1 ...        |
     +------------------------------------------+
     ^                                   ^
     +-----------+                       |
                 |                       |
ssl->hs_reader:  |                       |
  +-- frag ------+                       |
  +-- { frag + frag_len }  --------------+
  |
  +-- { acc + acc_avail } ----------------------------+
  +-- end    -------------------------------+         |
  +-- commit -+                             |         |
  |           v                             v         v
  +- acc --> +------------------------------------------+
             |HS hdr| reassembled msg k     | msg k + 1 |
             +------------------------------------------+
```

Specifically, the entire message `k` and the beginning of message `k+1` are in
the accumulator of the MPS reader.

2. When `ssl_consume_current_message` is called, it invokes `mbedtls_reader_commit`,
   which moves the `commit` pointer to the `end` pointer:

```
ssl:

  .. omitted for clarity ..

ssl->hs_reader:  |              |
  +-- frag ------+              |
  +-- { frag + frag_len }  -----+
  |
  +-- { acc + acc_avail } ----------------------------+
  +-- end    -------------------------------+         |
  +-- commit -------------------------------+         |
  |                                         v         v
  +- acc --> +------------------------------------------+
             |HS hdr| reassembled msg k     | msg k + 1 |
             +------------------------------------------+
```

3. After invoking `mbedtls_reader_commit`, `ssl_consume_current_message` invokes
   `mbedtls_reader_reclaim`, which frees the committed portion of the accumulator:

```
ssl:

  .. omitted for clarity ..

ssl->hs_reader:  |              |
  +-- frag ------+              |
  +-- { frag + frag_len }  -----+
  |
  +-- { acc + acc_avail } ---+
  +-- end    +               |
  +-- commit +               |
  |          v               v
  +- acc --> +------------------------------------------+
             | msg k + 1                                |
             +------------------------------------------+
```
