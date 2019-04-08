
#include <iostream>
#include "catch.hpp"

#include "../../src/shared/connection_manager.h"

#include "../../src/shared/requests.h"

using namespace helloworld;

TEST_CASE("Client parses request, server reads request no session key") {
    RSAKeyGen keyGenClient;
    keyGenClient.savePrivateKeyPassword("client-priv.pem", "123456789");
    keyGenClient.savePublicKey("client-pub.pem");

    ClientToServerManager client{"323994cfb9da285a5d9642e1759b224a", "server_pub.pem"};
    GenericServerManager server{"server_priv.pem", "323994cfb9da285a5d9642e1759b224a", "2b7e151628aed2a6abf7158809cf4f3c"};

    AuthenticateRequest registration("alice", {});
    Request request{{Request::Type::LOGIN, 5, 28}, registration.serialize()};

    Request result = server.parseIncoming(client.parseOutgoing(request));
    CHECK(result.header.type == request.header.type);
    //CHECK(result.header.messageNumber == request.header.messageNumber);
    CHECK(result.header.userId == request.header.userId);

    //generic parser has added the session key
    registration.sessionKey = "323994cfb9da285a5d9642e1759b224a";
    CHECK(result.payload == registration.serialize());
}

TEST_CASE("Client parses request, server reads request session key") {
    ClientToServerManager client{"73bed6b8e3c1743b7116e69e22229516", "server_pub.pem"};
    client.switchSecureChannel(true); //enable secure channel

    ServerToClientManager server{"73bed6b8e3c1743b7116e69e22229516"};

    Request request{{Request::Type::REMOVE, 20, 1111}, std::vector<unsigned char>{5,15,15,1,99,32,13,13,15,6,51,32,13,2}};

    Request result = server.parseIncoming(client.parseOutgoing(request));
    CHECK(result.header.type == request.header.type);
    //CHECK(result.header.messageNumber == request.header.messageNumber);
    CHECK(result.header.userId == request.header.userId);
    CHECK(result.payload == request.payload);
}

TEST_CASE("Server parses response, client reads response session key") {
    ClientToServerManager client{"73bed6b8e3c1743b7116e69e22229516", "server_pub.pem"};
    client.switchSecureChannel(true); //enable secure channel

    ServerToClientManager server{"73bed6b8e3c1743b7116e69e22229516"};

    Response response{{Response::Type::DATABASE_NOT_FOUD, 20, 1111},
                      std::vector<unsigned char>{5,15,15,1,99,32,13,13,15,6,51,32,13,2}};

    Response result = client.parseIncoming(server.parseOutgoing(response));
    CHECK(result.header.type == response.header.type);
    //CHECK(result.header.messageNumber == response.header.messageNumber);
    CHECK(result.header.userId == response.header.userId);
    CHECK(result.payload == response.payload);
}