#include <iostream>

#include "mbedtls/aes.h"

int main(int /* argc */, char** /* argv */) {
  mbedtls_aes_context x;
  mbedtls_aes_init(&x);
  mbedtls_aes_free(&x);

  std::cout << "This is client application.\n";
}
