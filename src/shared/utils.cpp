//
// Created by horak_000 on 10. 3. 2019.
//

#include "utils.h"

namespace helloworld {

    size_t read_n(std::istream &in, unsigned char *data, size_t length) {
        in.read((char *) data, length);
        return static_cast<size_t>(in.gcount());
    }

    void write_n(std::ostream &out, unsigned char *data, size_t length) {
        out.write((char *) data, length);
    }
}
