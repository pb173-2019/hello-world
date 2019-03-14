#include <iostream>
#include "mbedtls/aes.h"

#include "../shared/rsa_2048.h"

int main(int /* argc */, char** /* argv */) {
  mbedtls_aes_context x;
  mbedtls_aes_init(&x);
  mbedtls_aes_free(&x);

  using namespace helloworld;
  RSA2048 rsa{};
  rsa.generateKeyPair();
  
  std::cout << "This is client application.\n";
}
