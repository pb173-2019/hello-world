#include "user_data.h"

namespace helloworld {

bool operator==(const UserData &a, const UserData &b) {
    return a.name == b.name && a.id == b.id;
}

bool operator!=(const UserData &a, const UserData &b) { return !(a == b); }

}    // namespace helloworld