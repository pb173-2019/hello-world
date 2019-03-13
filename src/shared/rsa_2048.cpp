#include "rsa_2048.h"

namespace helloworld {


    void RSA2048::setKey(const std::string &key) {


        unsigned char keydata[]{ 1, 2, 3};

        mbedtls_pk_parse_key( &this->key, keydata, 3, nullptr, 0 );
    }

    std::vector<unsigned char> RSA2048::encrypt(const std::string &msg){
    }

    std::string RSA2048::decrypt(const std::vector<unsigned char> &data){
    }

    std::vector<unsigned char> RSA2048::sign(const std::string &hash){
    }

    bool RSA2048::verify(const std::vector<unsigned char> &signedData,
                        const std::string &hash){
    }

} //namespace helloworld

