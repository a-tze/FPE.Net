Format-Preserving Encryption for .NET
=====================================

This library implements the FF1 method for format-preserving encryption
specified in NIST Special Publication 800-38G, Recommendation for Block
Cipher Modes of Operation: Methods for Format-Preserving Encryption.
   
  
**The implementations focus on conformance, rather than on security or
performance, and as such they may not be suitable for real-world use with
sensitive data.**

**At the time of writing, some attacks against FF3 have been rumored about.
Therefore the algorithm has not been ported to .NET.**

Export restrictions
-------------------

This distribution includes cryptographic software. The country in which you
currently reside may have restrictions on the import, possession, use, and/or
re-export to another country, of encryption software. BEFORE using any
encryption software, please check your country's laws, regulations and
policies concerning the import, possession, or use, and re-export of
encryption software, to see if this is permitted. See
<http://www.wassenaar.org/> for more information.

License
-------

Copyright (c) 2016 Weydstone LLC dba Sutton Abinger
Copyright (c) 2018 Matthias Hunstock (.NET port, remove FF3)

See the NOTICE file distributed with this work for additional information
regarding copyright ownership. Matthias Hunstock licenses this file to you under
the Apache License, Version 2.0 (the "License"); you may not use this file
except in compliance with the License. You may obtain a copy of the License
at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.

Acknowledgements
----------------

The original author thanks Morris Dworkin and the Computer Security
Division, Information Technology Laboratory at National Institute of
Standards and Technology for their kind assistance in interpreting the
specification.

Additional Resources
--------------------

NIST Special Publication 800-38G, "Recommendation for Block Cipher Modes of
Operation: Methods for Format-Preserving Encryption" is available free of
charge from: http://dx.doi.org/10.6028/NIST.SP.800-38G.

Sample data for FF1 and FF3 are available at the examples page on NIST’s
Computer Security Resource Center website:
http://csrc.nist.gov/groups/ST/toolkit/examples.html.

What is FPE
-----------

Common block cipher modes of encryption, such as AES, take fixed-length
blocks of plaintext bytes as input and produce blocks of the same size
ciphertext as output. Padding and block chaining modes allow block ciphers to
be used to encrypt streams of data of arbitrary length.

In some circumstances, e.g. when working with legacy environments, it is
necessary to produce ciphertext in the same format and length, using the same
set of symbols as the original plaintext. For example, a payment account
number (PAN) consists of up to 19 decimal digits, with the first 6 digits
used to identify the payment scheme and issuing bank, and the final digit
used as a checksum using the Luhn algorithm. A card payment processor may
need to encrypt these PANs in a way that the ciphertext retains some or all
of the original attributes of the plaintext, so that systems designed to
process the plaintext may also process the ciphertext.

Format-preserving encryption (FPE) methods take strings of symbols as
plaintext input, and produce ciphertext output of the same length as the
input using the same set of symbols as the input. For the example above, this
would allow a card payment processor to encrypt PANs yet retain the same
format and structure in the ciphertext as in the plaintext.


Usage
-----

The FF1 (and FF3) methods operate on several parameters:
  * `radix`, the range of integer symbols `[0..radix-1]` used in the input and
output
  * `K`, an AES encryption key
  * `T`, an array of bytes used as an arbitrary "tweak," which is not necessarily secret but which extends and modifies the key
  * `X`, an array of integer symbols, each within the range `[0..radix-1]`

While FF3 uses a fixed-length 8 byte tweak, FF1 accepts an additional parameter:
  * `maxTlen`, the maximum length of `T`; any length of `T` in the range `[0..maxTlen]` is accepted

Both FF1 and FF3 output arrays of integer symbols, with length equal to the
input length, and with each symbol in the range `[0..radix-1]`.

It is up to the caller to convert between arbitrary data formats, e.g.
character-based data, and the arrays of integers that the FF1 and FF3
functions use for plaintext and ciphertext input and output. For example, a
caller might convert input using the symbols `[0123456789BCDFGHJKLMNPQRSTVWXZ]`
(i.e. the character set for the Natural Area Code) into the integer symbols
`[0..29]`, and reverse the conversion using the output.

The FF1 and FF3 methods operate only on uniform arrays of symbols where each
symbol is in the same range. They do not preserve data formats where the set
of symbols varies depending on the position within the input, such as for
example a license plate number of one decimal digit followed by three upper
case letters followed by three decimal digits. If necessary, the caller may
transform such input into uniform symbols, then reverse the transformation to
restore the original formatting.

This implementation focuses on conformance with the algorithms defined in
NIST SP 800-38G, with naming and structure closely aligned to the definitions
in NIST SP 800-38G. As such, variable names in the code defy naming
conventions in favor of the naming conventions used in NIST SP 800-38G.
So, for example, we use `x` to represent an integer and `X` to represent an
array of integers or bytes (i.e. bits), even though this does not follow the
conventions. 

NIST SP 800-38G uses mathematical symbols for some of its notations, which
require alternative naming. In the implementation, these are replaced
with descriptive method names. So, for example, the notation
"&lfloor;x&rfloor;" becomes `floor(x)` in the implementation.

In some places, NIST SP 800-38G uses superscripts and subscripts to specify
additional parameters. So, for example, "STR<sup>m</sup><sub>radix</sub>(x)"
becomes "str(x,radix,m)" in the implementation.

Data Types
----------

NIST SP 800-38G is written in terms of abstract data types, for which we have
chosen specific data types in the implementation.

We use arrays of bytes in place of the bit string type described in NIST SP
800-38G. This implies that bit strings must have a length that is a multiple
of 8 bits, but this is consistent with NIST SP 800-38G. (In fact, NIST SP
800-38G may have been clearer if it were written in terms of bytes rather
than bits -- see `ERRATA.txt`.)

We implement the numeral string in NIST SP 800-38G as an array of integers.
The range of values for numerals in NIST SP 800-38G is 0..2<sup>radix</sup>,
i.e. zero through 2<sup>2</sup>..2<sup>16</sup>, so all the values may be
represented using 32-bit signed integers.

Integers in NIST SP 800-38G are implicitly non-negative whole numbers of
arbitrary size, so we represent them using the BigInteger class.

As in NIST SP 800-38G, a block is a bit string (i.e. byte string) whose
length is the block size of the block cipher (i.e. 128 bits or 16 bytes). We
represent these as arrays of multiples of 16 bytes, without any special type.
Note that the **block** size for AES, which is the approved block cipher, is 128
bits regardless of the **key** size.

As described in NIST SP 800-38G, a block string is an array of bits (i.e.
bytes) whose length is a multiple of the block size of the block cipher. We
represent this as an array of bytes with a length that is a multiple of 16, again without any special type.

Native Functions
----------------

Instead of implementing new LEN(X) functions for bit strings and numeral
strings, we use the Length property of the array type. For byte strings the
Length property is the BYTELEN(X) value, and the value of LEN(X) is X.Length/8.
(Again, there is an assumption in NIST SP 800-38G that bit strings are
multiples of 8 bits.)

Instead of the mod calculation described in NIST SP 800-38G, we use the
basically the BigInteger.mod() methods. Note: the .NET BigInteger mod operation
returns negative results for negative dividend operands. This behaviour is
corrected in a wrapper method.

The bit string conversion in NIST SP 800-38G is only used with constant
inputs, so we sometimes use inline constants in place of the function where
this can improve readability.

The PRF(X) function used in FF1 is an implementation of the AES CBC mode
without padding, followed by the extraction of the final block of the cipher.
We have provided both the direct implementation of the PRF(X) function as
`Ciphers.prf(X)` and an implementation that uses an AES Cipher object in
`Ciphers.prf2(X)`.

Unit Tests
----------

The Unit tests are written to validate inputs and outputs using the sample
data for FF1 and FF3 provided by NIST, as well as to provide code coverage
and to fully exercise the functions. Sample data for FF1 and FF3 are 
available at the examples page on NIST’s
Computer Security Resource Center website:
[http://csrc.nist.gov/groups/ST/toolkit/examples.html">http://csrc.nist.gov/groups/ST/toolkit/examples.html]
