//
// Created by ivan on 30.3.19.
//
#include "hkdf.h"
#include "utils.h"
#include <cmath>

using namespace helloworld;

std::string hkdf::_extract(const std::string &IKM, const std::string &salt) const {
    _hash->setKey(salt);
    return to_hex(_hash->generate(from_hex(IKM)));
}

std::string hkdf::_expand(const std::string &PRK, const std::string &info, size_t len) const {
    auto N = static_cast<size_t >(ceil(static_cast<double>(len) / _hash->hmacLength()));
    _hash->setKey(PRK);
    std::vector<unsigned char> T;

    std::vector<unsigned char> prevT;
    for (size_t i = 0u; i < N; i++) {
        std::copy(info.begin(), info.end(), std::back_inserter(prevT));
        prevT.push_back(i + 1);

        prevT = _hash->generate(prevT);

        std::copy(prevT.begin(), prevT.end(), std::back_inserter(T));
    }
    return to_hex(T).substr(0, len * 2);
}

hkdf::hkdf(std::unique_ptr<hmac> &&hash, std::string info)
        : _hash(std::move(hash)), _salt(_hash->hmacLength(), 0), _info(std::move(info)) {
}

void hkdf::setSalt(const std::string &newSalt) {
    _salt = newSalt;
}

std::string hkdf::generate(const std::string &InputKeyingMaterial, size_t outputLength) const {
    return _expand(_extract(InputKeyingMaterial, _salt), _info, outputLength);
}
