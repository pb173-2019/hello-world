//
// Created by ivan on 30.3.19.
//
#include "hkdf.h"
#include "utils.h"
#include <cmath>

using namespace helloworld;

zero::str_t hkdf::_extract(const zero::str_t &IKM, const zero::str_t &salt) const {
    _hash->setKey(salt);
    return to_hex(_hash->generate(from_hex(IKM)));
}

zero::str_t hkdf::_expand(const zero::str_t &PRK, const zero::str_t &info, size_t len) const {
    auto N = static_cast<size_t >(ceil(static_cast<double>(len) / _hash->hmacLength()));
    _hash->setKey(PRK);
    zero::bytes_t T;

    zero::bytes_t prevT;
    for (size_t i = 0u; i < N; i++) {
        std::copy(info.begin(), info.end(), std::back_inserter(prevT));
        prevT.push_back(static_cast<unsigned char &&>(i + 1));
        prevT = _hash->generate(prevT);

        std::copy(prevT.begin(), prevT.end(), std::back_inserter(T));
    }
    return to_hex(T).substr(0, len * 2);
}

hkdf::hkdf(std::unique_ptr<hmac> &&hash, zero::str_t info)
        : _hash(std::move(hash)), _salt(_hash->hmacLength(), 0), _info(std::move(info)) {
}

void hkdf::setSalt(const zero::str_t &newSalt) {
    _salt = newSalt;
}

zero::str_t hkdf::generate(const zero::str_t &InputKeyingMaterial, size_t outputLength) const {
    return _expand(_extract(InputKeyingMaterial, _salt), _info, outputLength);
}
