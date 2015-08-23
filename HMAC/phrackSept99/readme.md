{verbatim article intro, echoed here w/ full attribution & proper respect for author Conehead ~ pj}



-------[  Phrack Magazine --- Vol. 9 | Issue 55 --- 09.09.99 --- 11 of 19  ]


-------------------------[  Stego Hasho  ]


--------[  Conehead  ]


----[  Introduction


The use of hash (checksum) functions in a design for encryption/decryption
systems is not export controlled by the U.S. government.  But even if hash
functions aren't allowed to be exported for confidentiality purposes at some
point in the future, there will still be a hidden way of accomplishing privacy
in their approved, exportable forms (unless the export of MACs also becomes
controlled).


----[  Integrity

The common use for a hash function (basically a one-way encryptor as opposed
to a two-way such as DES or RSA, taking a variable sized message and reducing
it to a set number of random bits) is to assure the integrity of a message
from sender to receiver (or anyone else for that matter).  The message and
its sender computed hash are sent across the network where the receiver
compares the received hash with the receiver computed hash using the shared
hash function against the received message.  If there's no match in the hashes,
he/she can assume the message is faulty.

1: H(message)---message,hash--->H(message)


----[  Authentication

While this provides for message integrity, it doesn't provide message
authentication.  Authentication of a message through a hash(generally only
between the sender and receiver) can be provided with the addition of a shared
secret key between the sender and receiver (possibly exchanged via
Diffie-Hellman) to the message (PGP accomplishes hash authentication through a
public key, usually allowing anyone to authenticate it).  The message (without
the key) and its sender computed hash (using the key) are sent across a wire
where the receiver compares the received hash with the receiver computed hash
using the shared hash function against the received message and the shared key.
This method still allows for deniability among keyholders.  With
authentication, use of a nonce in the hash should also be considered to avoid
a replay attack.  Obviously, anyone only using the hash function against the
message to produce this hash will find no match.  He/she may then assume its a
MAC (message authentication code). If there's no match in the hashes, the
receiver might not know whether the integrity and/or authentication is to
blame.

2: H(message+key)---message,hash--->H(message+key)

A mandatory construction of protocol 2 for internet security protocols is
Bellare's HMAC.

3: H(key XOR opad,H(key XOR ipad,message))


----[  Confidentiality

While a hash MAC provides for message integrity and authentication, there is no
confidentiality to the message using this method.  However, a form of message
confidentiality using hashes can be achieved with the addition of a few simple
steps.  In addition to the message and key, the sender will also add a secret
message to be hashed.  The message (without the key and secret message) and its
sender computed hash (using the key and secret message) are sent across a wire
where the receiver compares the received hash with the receiver computed hash
using the shared hash function against the received message, shared key, and
secret message.  A receiver may first wish to check if the hash is a MAC, then
look for a secret message.  If there's no match in the hashes, he/she might not
know whether the integrity, authentication, and/or failure to determine the
secret is to blame.

4: H(public message+key+secret message)---public message,hash--->H(public
   message+key+secret message)

For HMAC, the secret message can be appended to the public message.

5: H(key XOR opad,H(key XOR ipad,public message+secret message))

The obvious question for the receiver is how to choose the right secret message
to get the hash to compute correctly.  The answer is to use a brute force
method using a dictionary of possible secret messages, a method similar to
those of password cracking programs with the public message used as the salt.
While this may sound unfeasible at first, the choice of a "secret message"
dictionary with a reasonable search space (its granularity via letters, words,
and/or phrases), the orderliness of the dictionary(sorted by most commonly
used to least), a decent hash speed (the size of the secret message is not a
factor), and/or performing the hash computations in parallel can simplify
brute forcing into a workable solution. In addition to figuring out the secret
message, integrity and authentication of both the public and secret messages
will also be guaranteed.


----[  Steganography

By now, it should be obvious from what is sent over the wire in protocols 2 and
4 that hash confidentiality also has a steganographic (hidden) property.
Hashes used as one-time pads or in wheat/chaff operations for confidentiality
don't possess this property.  In a variation on this method, another stego
version of this would be to take out the public message.  Some applications
such as S/key only send hashes over the wire at certain points in their
protocols.

6: H(key+secret message)---hash--->H(key+secret message)

The strength of the encryption method lies in the strength of the underlying
MAC (hash function, key length, key reuse, and construction).  The strength of
the steganographic method lies in giving the impression that only a MAC is
being used: minimizing public message reuse, keeping others ignorant of the
stego hasho construction formula, and using the most conservative number of
stego hashes to convey a large message(this relates to dictionary granularity).
If secret messages need to be tied together in sequential order to form a
larger message, using a nonce such as a timestamp in each message for
sequencing will suffice (or adopting an external sequence number such as is
found in network packets).  The stego property can still be maintained because
MACs use nonces.  Examples where a larger message could be sent without much
suspicion could involve a stream of authenticated IPv6 packets or the transfer
of a list of files and their corresponding checksums.  As far as cryptanalysis,
steganalysis, and other attacks are concerned, strong hash function and
construction is important. Also, frequent changes in the public message and
secret key help.  If a particular hash or construction flaw causes the
encryption to be broken, change to a more secure one. However, old secret
messages may be compromised.

It's kind of ironic that this is a stego method based on embedding a secret
into ciphertext (hash), based on a misguided notion as to the ciphertext's
function.  Other stego methods(such as using image bits) are weaker and may
involve more overhead, though they may be strengthened by encrypting the
embedded secret.

Example of stego hasho with HMAC construction (source available from RFC2104)
using MD5 hash (source available from RFC1321) and on-line English dictionary
(source available from your local cracker).
