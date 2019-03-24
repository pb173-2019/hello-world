#include "aes_128.h"
#include "utils.h"
#include "random.h"

namespace helloworld {

void AES128::encrypt(std::istream &in, std::ostream &out) {
    if (dirty) {
        _reset();
    }
    _init(true);
    dirty = true;
    _process(in, out);
}

void AES128::decrypt(std::istream &in, std::ostream &out) {
    if (dirty) {
        _reset();
    }
    _init(false);
    dirty = true;
    _process(in, out);
}



} //namespace helloworld