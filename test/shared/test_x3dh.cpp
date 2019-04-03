#include <iostream>
#include "catch.hpp"

#include "../../src/shared/X3DH.h"

void appendVector(std::vector<unsigned char>& to, const std::vector<unsigned char> &from) {
    to.insert(to.end(), from.begin(), from.end());
}

using namespace helloworld;

TEST_CASE("X3DH process test") {
    //X3DH assumes the files with public key saved in identityKey.key, identityKey.pub

    C25519KeyGen keyGen; //alice's identity keys
    keyGen.savePrivateKeyPassword("alice" + idC25519priv, "1234");
    keyGen.savePublicKey("alice" + idC25519pub);

    C25519KeyGen bobIdentity;
    C25519KeyGen bobPreKey;
    C25519KeyGen bobOneTime1;
    C25519KeyGen bobOneTime2;

    C25519 identity;
    identity.setPrivateKey(bobIdentity);

    KeyBundle<C25519> bundle;
    bundle.identityKey = bobIdentity.getPublicKey();
    bundle.preKey = bobPreKey.getPublicKey();
    bundle.preKeySingiture = identity.sign(bundle.preKey);
    bundle.oneTimeKeys = std::vector<KeyBundle<C25519>::key_t>{
        bobOneTime1.getPublicKey(),
        bobOneTime2.getPublicKey()
    };

    X3DHRequest<C25519> toFill;

    SendData toSend{"1.3.2013", "user", {1, 2, 3, 4}};
    SendData transfered;

    X3DH x3dh;
    std::string shared = x3dh.out("alice", "1234", bundle, toSend, toFill);

    std::cout << shared << "\n";

    SECTION("SIMULATE receiver") {
        CHECK(shared.size() == 32);
        REQUIRE(toFill.opKeyUsed == 0x01);
        REQUIRE(toFill.opKeyId == 1);

        std::vector <unsigned char> dhs;

        // DH1 step
        C25519 dhcurve;
        dhcurve.setPrivateKey(bobPreKey);
        dhcurve.setPublicKey(toFill.senderIdPubKey);
        dhs = dhcurve.getShared();

        //DH2 step
        identity.setPublicKey(toFill.senderEphermalPubKey);
        appendVector(dhs, identity.getShared());

        //DH3
        dhcurve.setPublicKey(toFill.senderEphermalPubKey);
        appendVector(dhs, dhcurve.getShared());

        //DH4 (optional)
        dhcurve.setPrivateKey(bobOneTime2);
        appendVector(dhs, dhcurve.getShared());

        hkdf kdf;
        std::string sk = kdf.generate(to_hex(dhs), 16);

        CHECK(sk == shared);

        AESGCM gcm;
        gcm.setKey(sk);
        gcm.setIv(to_hex(toFill.senderEphermalPubKey).substr(0, 24));

        std::stringstream toDecrypt{};
        std::stringstream result{};
        std::stringstream ad{to_hex(toFill.senderIdPubKey) + to_hex(bundle.identityKey)};
        write_n(toDecrypt, toFill.AEADenrypted);

        gcm.decryptWithAd(toDecrypt, ad, result);

        size_t size = getSize(result);
        std::vector<unsigned char> resultBytes(size);
        size_t read = read_n(result, resultBytes.data(), size);
        CHECK(read == size);

        transfered = SendData::deserialize(resultBytes);
    }

    SECTION("ACTUAL receiver") {
        Response r{{Response::Type::RECEIVE, 0, 0}, toFill.serialize()};

        bobIdentity.savePublicKey("bob" + idC25519pub);
        bobIdentity.savePrivateKeyPassword("bob" + idC25519priv, "1234");

        bobPreKey.savePublicKey("bob" + preC25519pub);
        bobPreKey.savePrivateKeyPassword("bob" + preC25519priv, "1234");

        bobOneTime2.savePublicKey("bob" + std::to_string(toFill.opKeyId) + oneTimeC25519pub);
        bobOneTime2.savePrivateKeyPassword("bob" + std::to_string(toFill.opKeyId) + oneTimeC25519priv, "1234");

        CHECK(x3dh.in("bob", "1234", transfered, r) == shared);
    }

    CHECK(transfered.from == toSend.from);
    CHECK(transfered.data == toSend.data);
    CHECK(transfered.date == toSend.date);
}



