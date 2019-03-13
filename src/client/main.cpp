#include <iostream>
#include "mbedtls/aes.h"

#include "../shared/base_64.h"
#include "../shared/utils.h"

int main(int /* argc */, char** /* argv */) {
  mbedtls_aes_context x;
  mbedtls_aes_init(&x);
  mbedtls_aes_free(&x);

  using namespace helloworld;
  Base64 b;
  b.encode(from_string("ahoj"));

  std::cout << "This is client application.\n";
}
