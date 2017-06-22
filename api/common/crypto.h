/* Copyright 2017 Outscale SAS
 *
 * This file is part of Butterfly.
 *
 * Butterfly is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation.
 *
 * Butterfly is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Butterfly.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef COMMON_CRYPTO_H_
#define COMMON_CRYPTO_H_

#include <string>

/* Encryption facility.

   # Format:

   - 1B: Encyption format version.
   - XB: All the next bytes are encrypted depending of the format version

   ## Version 0: (unencrypted)

   - XB: All bytes corresponds to the clear message

   ## Version 1:

   - 16B: Initialization Vector (this information does not need to be secret)

    All the following data is encrypted using AES-256 in CBC mode:

   - 64B: SHA-512 of message content (only to check content integrity)
   - XB: message content
   - Byte-padding in [PKCS7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7)
 */

namespace Crypto {

enum Version {
    CLEAR = 0,
    EAS256CBC_SHA512 = 1,
    MAX = 2,
};

class Crypto {
    public:
    Crypto();
    std::string key;
    void Allow(enum Version version);
    void Block(enum Version version);
    bool Allowed(enum Version version);
    bool Encrypt(std::string clear, char **encrypted, size_t *encrypted_size);
    void ClearCode(std::string clear, char **encrypted, size_t *encrypted_size);
    bool Decrypt(const char *encrypted, size_t encrypted_size,
                 std::string *clear);

    private:
    bool allowed_[MAX];
    bool Encrypt0(const char *c, size_t cs, char **e, size_t *es);
    bool Decrypt0(const char *e, size_t es, char **c, size_t *cs);
    bool Encrypt1(const char *c, size_t cs, char **e, size_t *es);
    bool Decrypt1(const char *e, size_t es, char **c, size_t *cs);
};
}
#endif // COMMON_CRYPTO_H_
