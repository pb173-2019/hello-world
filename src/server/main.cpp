#include <iostream>
#include <sstream>

#include "../shared/request_response.h"
#include "../shared/aes_gcm.h"

int main(int /* argc */, char ** /* argv */) {
    using namespace helloworld;

    Request request{{Request::Type::CREATE, 0}, std::vector<unsigned char>(10)};
    std::vector<unsigned char> head_data = request.header.serialize();
    std::stringstream head;
    write_n(head, head_data);
    std::cout << "Head stream size:" << getSize(head) << "\n";

    Random _random;
    AESGCM _gcm;
    _gcm.setKey("FEFFE9928665731C6D6A8F9467308308");

    std::string headIv = to_hex(_random.get(AESGCM::iv_size));
    std::istringstream headIvStream{headIv};
    _gcm.setIv(headIv);


    std::stringstream result;

    std::cout << "IV head stream size:" << getSize(headIvStream) << "\n";
    _gcm.encryptWithAd(head, headIvStream, result);
    result.seekg(0, std::ios::beg);
    std::cout << "Head encrypted stream size:" << getSize(result) << "\n";

    std::stringstream data{"adkuhelgkvsjdcaxs"};
    std::cout << "Data len: " << data.str().size() << "\n";
    data.seekg(0, std::ios::beg);
    std::cout << "Data len: " << getSize(data) << "\n";

    std::cout << "This is server application.\n";
}
