/*
 * OpenVPN Protocol, taken from ssl.h in OpenVPN source code.
 *
 * TCP/UDP Packet:  This represents the top-level encapsulation.
 *
 * TCP/UDP packet format:
 *
 *   Packet length (16 bits, unsigned) -- TCP only, always sent as
 *       plaintext.  Since TCP is a stream protocol, the packet
 *       length words define the packetization of the stream.
 *
 *   Packet opcode/key_id (8 bits) -- TLS only, not used in
 *       pre-shared secret mode.
 *            packet message type, a P_* constant (high 5 bits)
 *            key_id (low 3 bits, see key_id in struct tls_session
 *              below for comment).  The key_id refers to an
 *              already negotiated TLS session.  OpenVPN seamlessly
 *              renegotiates the TLS session by using a new key_id
 *              for the new session.  Overlap (controlled by
 *              user definable parameters) between old and new TLS
 *              sessions is allowed, providing a seamless transition
 *              during tunnel operation.
 *
 *   Payload (n bytes), which may be a P_CONTROL, P_ACK, or P_DATA
 *       message.
 *
 * Message types:
 *
 *  P_CONTROL_HARD_RESET_CLIENT_V1 -- Key method 1, initial key from
 *    client, forget previous state.
 *
 *  P_CONTROL_HARD_RESET_SERVER_V1 -- Key method 1, initial key
 *    from server, forget previous state.
 *
 *  P_CONTROL_SOFT_RESET_V1 -- New key, with a graceful transition
 *    from old to new key in the sense that a transition window
 *    exists where both the old or new key_id can be used.  OpenVPN
 *    uses two different forms of key_id.  The first form is 64 bits
 *    and is used for all P_CONTROL messages.  P_DATA messages on the
 *    other hand use a shortened key_id of 3 bits for efficiency
 *    reasons since the vast majority of OpenVPN packets in an
 *    active tunnel will be P_DATA messages.  The 64 bit form
 *    is referred to as a session_id, while the 3 bit form is
 *    referred to as a key_id.
 *
 *  P_CONTROL_V1 -- Control channel packet (usually TLS ciphertext).
 *
 *  P_ACK_V1 -- Acknowledgement for P_CONTROL packets received.
 *
 *  P_DATA_V1 -- Data channel packet containing actual tunnel data
 *    ciphertext.
 *
 *  P_CONTROL_HARD_RESET_CLIENT_V2 -- Key method 2, initial key from
 *   client, forget previous state.
 *
 *  P_CONTROL_HARD_RESET_SERVER_V2 -- Key method 2, initial key from
 *   server, forget previous state.
 *
 * P_CONTROL* and P_ACK Payload:  The P_CONTROL message type
 * indicates a TLS ciphertext packet which has been encapsulated
 * inside of a reliability layer.  The reliability layer is
 * implemented as a straightforward ACK and retransmit model.
 *
 * P_CONTROL message format:
 *
 *   local session_id (random 64 bit value to identify TLS session).
 *   HMAC signature of entire encapsulation header for integrity
 *       check if --tls-auth is specified (usually 16 or 20 bytes).
 *   packet-id for replay protection (4 or 8 bytes, includes
 *       sequence number and optional time_t timestamp).
 *   P_ACK packet_id array length (1 byte).
 *   P_ACK packet-id array (if length > 0).
 *   P_ACK remote session_id (if length > 0).
 *   message packet-id (4 bytes).
 *   TLS payload ciphertext (n bytes) (only for P_CONTROL).
 *
 * Once the TLS session has been initialized and authenticated,
 * the TLS channel is used to exchange random key material for
 * bidirectional cipher and HMAC keys which will be
 * used to secure actual tunnel packets.  OpenVPN currently
 * implements two key methods.  Key method 1 directly
 * derives keys using random bits obtained from the RAND_bytes
 * OpenSSL function.  Key method 2 mixes random key material
 * from both sides of the connection using the TLS PRF mixing
 * function.  Key method 2 is the preferred method and is the default
 * for OpenVPN 2.0.
 * 
 * TLS plaintext content:
 *
 * TLS plaintext packet (if key_method == 1):
 *
 *   Cipher key length in bytes (1 byte).
 *   Cipher key (n bytes).
 *   HMAC key length in bytes (1 byte).
 *   HMAC key (n bytes).
 *   Options string (n bytes, null terminated, client/server options
 *       string should match).
 *
 * TLS plaintext packet (if key_method == 2):
 *
 *   Literal 0 (4 bytes).
 *   key_method type (1 byte).
 *   key_source structure (pre_master only defined for client ->
 *       server).
 *   options_string_length, including null (2 bytes).
 *   Options string (n bytes, null terminated, client/server options
 *       string must match).
 *   [The username/password data below is optional, record can end
 *       at this point.]
 *   username_string_length, including null (2 bytes).
 *   Username string (n bytes, null terminated).
 *   password_string_length, including null (2 bytes).
 *   Password string (n bytes, null terminated).
 *
 * The P_DATA payload represents encrypted, encapsulated tunnel
 * packets which tend to be either IP packets or Ethernet frames.
 * This is essentially the "payload" of the VPN.
 *
 * P_DATA message content:
 *   HMAC of ciphertext IV + ciphertext (if not disabled by
 *       --auth none).
 *   Ciphertext IV (size is cipher-dependent, if not disabled by
 *       --no-iv).
 *   Tunnel packet ciphertext.
 *
 * P_DATA plaintext
 *   packet_id (4 or 8 bytes, if not disabled by --no-replay).
 *       In SSL/TLS mode, 4 bytes are used because the implementation
 *       can force a TLS renegotation before 2^32 packets are sent.
 *       In pre-shared key mode, 8 bytes are used (sequence number
 *       and time_t value) to allow long-term key usage without
 *       packet_id collisions.
 *   User plaintext (n bytes).
 *
 * Notes:
 *   (1) ACK messages can be encoded in either the dedicated
 *       P_ACK record or they can be prepended to a P_CONTROL message.
 *   (2) P_DATA and P_CONTROL/P_ACK use independent packet-id
 *       sequences because P_DATA is an unreliable channel while
 *       P_CONTROL/P_ACK is a reliable channel.  Each use their
 *       own independent HMAC keys.
 *   (3) Note that when --tls-auth is used, all message types are
 *       protected with an HMAC signature, even the initial packets
 *       of the TLS handshake.  This makes it easy for OpenVPN to
 *       throw away bogus packets quickly, without wasting resources
 *       on attempting a TLS handshake which will ultimately fail.
 */
