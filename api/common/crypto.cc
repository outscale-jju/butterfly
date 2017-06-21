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

#include <cstring>
#include "crypto.h"

namespace Crypto {

Crypto::Crypto() {
    for (int i = 0; i < MAX; i++) {
        allowed_[i] = false;
    }
}

void Crypto::Allow(enum Version version) {
    allowed_[version] = true;
}

void Crypto::Block(enum Version version) {
    allowed_[version] = false;
}

bool Crypto::Allowed(enum Version version) {
    return allowed_[version];
}

bool Crypto::Encrypt(std::string c, char **e, size_t *es) {
    enum Version v = CLEAR;

    if (key.length() > 0) {
        for (int i = MAX - 1; i != 0; i--) {
            if (allowed_[i]) {
                v = static_cast<enum Version>(i);
                break;
            }
        }
    }
    if (!allowed_[v]) {
        return false;
    }

    switch (v) {
        case CLEAR: return Encrypt0(c.c_str(), c.length(), e, es);
        break;
        default: break;
    }
    return false;
}

void Crypto::ClearCode(std::string c, char **e, size_t *es) {
    Encrypt0(c.c_str(), c.length() + 1, e, es);
}

bool Crypto::Decrypt(const char *e, size_t es, std::string *clear) {
    if (!e || es < 2)
        return false;
    enum Version v = static_cast<enum Version>(e[0]);
    if (!allowed_[v]) {
        return false;
    }
    char *c = NULL;
    size_t cs = 0;
    bool ret = false;
    switch (v) {
        case CLEAR: ret = Decrypt0(e, es, &c, &cs);
        break;
        default: break;
    }
    if (!ret)
        return false;
    if (!c || !cs)
        return false;
    for (size_t i = 0; i < cs; i++)
        *clear += c[i];
    free(c);
    return true;
}

bool Crypto::Encrypt0(const char *c, size_t cs, char **e, size_t *es) {
    *es = cs + 1;
    *e = new char[*es];
    *e[0] = 0x00;
    std::memcpy(*e + 1, c, cs);
    return true;
}

bool Crypto::Decrypt0(const char *e, size_t es, char **c, size_t *cs) {
    *cs = es - 1;
    *c = new char[*cs];
    std::memcpy(*c, e + 1, *cs);
    return true;
}
}
