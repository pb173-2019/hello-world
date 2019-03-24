#include <iostream>
#include "catch.hpp"

#include "../../src/shared/connection_manager.h"

using namespace helloworld;

TEST_CASE("Client parses request, server reads request no session key") {
    RSAKeyGen keyGenClient;
    keyGenClient.savePrivateKeyPassword("client-priv.pem", "123456789");
    keyGenClient.savePublicKey("client-pub.pem");

    RSAKeyGen keyGenServer;
    keyGenServer.savePrivateKeyPassword("server-priv.pem", "nezname-heslo");
    keyGenServer.savePublicKey("server-pub.pem");

    ClientToServerManager client{"server-pub.pem", "client-priv.pem", "123456789"};
    ServerToClientManager server{"client-pub.pem", "server-priv.pem", "nezname-heslo"};

    Request request{{Request::Type::LOGIN, 5, 28}, std::vector<unsigned char>{1,5,6,132,1,56,1,5,8}};

    Request result = server.parseIncoming(client.parseOutgoing(request));
    CHECK(result.header.type == request.header.type);
    CHECK(result.header.messageNumber == request.header.messageNumber);
    CHECK(result.header.userId == request.header.userId);
    CHECK(result.payload == request.payload);
}

TEST_CASE("Client parses request, server reads request session key") {
    ClientToServerManager client{"server-pub.pem", "client-priv.pem", "123456789"};
    ServerToClientManager server{"client-pub.pem", "server-priv.pem", "nezname-heslo"};

    Request request{{Request::Type::DELETE, 20, 1111}, std::vector<unsigned char>{5,15,15,1,99,32,13,13,15,6,51,32,13,2}};

    client.openSecureChannel("73bed6b8e3c1743b7116e69e22229516");
    server.openSecureChannel("73bed6b8e3c1743b7116e69e22229516");

    Request result = server.parseIncoming(client.parseOutgoing(request));
    CHECK(result.header.type == request.header.type);
    CHECK(result.header.messageNumber == request.header.messageNumber);
    CHECK(result.header.userId == request.header.userId);
    CHECK(result.payload == request.payload);
}

TEST_CASE("Server parses response, client reads response no session key") {
    ClientToServerManager client{"server-pub.pem", "client-priv.pem", "123456789"};
    ServerToClientManager server{"client-pub.pem", "server-priv.pem", "nezname-heslo"};

    Response response{{Response::Type::INVALID_AUTH, 5, 28}, std::vector<unsigned char>{1,5,6,132,1,56,1,5,8}};

    Response result = client.parseIncoming(server.parseOutgoing(response));
    CHECK(result.header.type == response.header.type);
    CHECK(result.header.messageNumber == response.header.messageNumber);
    CHECK(result.header.userId == response.header.userId);
    CHECK(result.payload == response.payload);
}

TEST_CASE("Server parses response, client reads response session key") {
    ClientToServerManager client{"server-pub.pem", "client-priv.pem", "123456789"};
    ServerToClientManager server{"client-pub.pem", "server-priv.pem", "nezname-heslo"};

    Response response{{Response::Type::DATABASE_NOT_FOUD, 20, 1111}, std::vector<unsigned char>{5,15,15,1,99,32,13,13,15,6,51,32,13,2}};

    client.openSecureChannel("73bed6b8e3c1743b7116e69e22229516");
    server.openSecureChannel("73bed6b8e3c1743b7116e69e22229516");

    Response result = client.parseIncoming(server.parseOutgoing(response));
    CHECK(result.header.type == response.header.type);
    CHECK(result.header.messageNumber == response.header.messageNumber);
    CHECK(result.header.userId == response.header.userId);
    CHECK(result.payload == response.payload);
}