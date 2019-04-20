#include "conf.h"

#include "../../src/shared/rsa_2048.h"

using namespace helloworld;
int main() {
    for (int i = 0; i < ROUNDS; i++) {
        RSAKeyGen keys{};
        keys.savePublicKey("alice_" + std::to_string(i) + "_.pem");
        keys.savePrivateKeyPassword("alice_" + std::to_string(i) + "_priv.pem", "1234");
    }
}