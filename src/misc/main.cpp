#include <string.h>
#include <iostream>
#include "../shared/rsa_2048.h"

using namespace helloworld;

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "Wrong number of arguments\n"
                     "./misc pass";
        return 1;
    }
    if (strlen(argv[1]) < 8) {
        std::cerr << "Password have to be at least 8 characters long";
    }
    RSAKeyGen rsa;
    rsa.savePrivateKeyPassword("server_priv.pem", argv[1]);
    rsa.savePublicKey("server_pub.pem");
    return 0;
}