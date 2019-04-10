#include <iostream>
#include "catch.hpp"

#include "../../src/shared/X3DH.h"

void appendVector(std::vector<unsigned char>& to, const std::vector<unsigned char> &from) {
    to.insert(to.end(), from.begin(), from.end());
}

using namespace helloworld;

TEST_CASE("X3DH process test one-time keys present") {
    //X3DH assumes the files with public key saved in identityKey.key, identityKey.pub

    std::string alice = "alice";
    std::string alice_pwd = "1234";

    C25519KeyGen keyGen; //alice's identity keys
    keyGen.savePrivateKeyPassword(alice + idC25519priv, alice_pwd);
    keyGen.savePublicKey(alice + idC25519pub);

    C25519KeyGen bobIdentity;
    C25519KeyGen bobPreKey;
    C25519KeyGen bobOneTime1;
    C25519KeyGen bobOneTime2;

    C25519 identity;
    identity.setPrivateKey(bobIdentity);

    KeyBundle<C25519> bundle;
    bundle.generateTimeStamp();
    bundle.identityKey = bobIdentity.getPublicKey();
    bundle.preKey = bobPreKey.getPublicKey();
    bundle.preKeySingiture = identity.sign(bundle.preKey);
    bundle.oneTimeKeys = std::vector<KeyBundle<C25519>::key_t>{
        bobOneTime1.getPublicKey(),
        bobOneTime2.getPublicKey()
    };

    SendData toSend{"1.3.2013", "user", {1, 2, 3, 4}};

    X3DH x3dh_alice(alice, alice_pwd);
    //setTimestamp() not needed in x3dh_alice as alice is not using .in()

    X3DHRequest<C25519> request;
    X3DH::X3DHSecretPubKey secret;
    std::tie(request, secret) = x3dh_alice.setSecret(bundle);

    SECTION("SIMULATE receiver") {
        CHECK(secret.sk.size() == 16);
        REQUIRE(request.opKeyUsed == 0x01);
        REQUIRE(request.opKeyId == 1);

        std::vector <unsigned char> dhs;

        // DH1 step
        C25519 dhcurve;
        dhcurve.setPrivateKey(bobPreKey);
        dhcurve.setPublicKey(request.senderIdPubKey);
        dhs = dhcurve.getShared();

        //DH2 step
        identity.setPublicKey(request.senderEphermalPubKey);
        appendVector(dhs, identity.getShared());

        //DH3
        dhcurve.setPublicKey(request.senderEphermalPubKey);
        appendVector(dhs, dhcurve.getShared());

        //DH4 (optional)
        dhcurve.setPrivateKey(bobOneTime2);
        appendVector(dhs, dhcurve.getShared());

        hkdf kdf;
        std::string sk = kdf.generate(to_hex(dhs), 16);

        CHECK(sk == to_hex(secret.sk));
    }

    SECTION("ACTUAL receiver current pwdSet") {
        std::string bob = "bob";
        std::string bob_pwd = "bob je svaloun";

        Response r{{Response::Type::RECEIVE, 0, 0}, request.serialize()};

        bobIdentity.savePublicKey(bob + idC25519pub);
        bobIdentity.savePrivateKeyPassword(bob + idC25519priv, bob_pwd);

        bobPreKey.savePublicKey(bob + preC25519pub);
        bobPreKey.savePrivateKeyPassword(bob + preC25519priv, bob_pwd);

        bobOneTime2.savePublicKey(bob + std::to_string(request.opKeyId) + oneTimeC25519pub);
        bobOneTime2.savePrivateKeyPassword(bob + std::to_string(request.opKeyId) + oneTimeC25519priv, bob_pwd);

        X3DH x3dh_bob(bob, bob_pwd);
        x3dh_bob.setTimestamp(bundle.timestamp);

        std::vector<unsigned char> messageEncrypted;
        X3DH::X3DHSecretKeyPair bob_secret;
        std::tie(messageEncrypted, bob_secret) = x3dh_bob.getSecret(r);

        CHECK(bob_secret.sk == secret.sk);
    }

    SECTION("ACTUAL receiver old pwdSet") {
        std::string bob = "bob";
        std::string bob_pwd = "bob je svaloun";

        Response r{{Response::Type::RECEIVE, 0, 0}, request.serialize()};

        bobIdentity.savePublicKey(bob + idC25519pub + ".old");
        bobIdentity.savePrivateKeyPassword(bob + idC25519priv + ".old", bob_pwd);

        bobPreKey.savePublicKey(bob + preC25519pub + ".old");
        bobPreKey.savePrivateKeyPassword(bob + preC25519priv + ".old", bob_pwd);

        bobOneTime2.savePublicKey(bob + std::to_string(request.opKeyId) + oneTimeC25519pub + ".old");
        bobOneTime2.savePrivateKeyPassword(bob + std::to_string(request.opKeyId) + oneTimeC25519priv + ".old", bob_pwd);

        X3DH x3dh_bob(bob, bob_pwd);
        x3dh_bob.setTimestamp(bundle.timestamp + 1); //different timestamp!

        std::vector<unsigned char> messageEncrypted;
        X3DH::X3DHSecretKeyPair bob_secret;
        std::tie(messageEncrypted, bob_secret) = x3dh_bob.getSecret(r);

        CHECK(bob_secret.sk == secret.sk);
    }
}

TEST_CASE("X3DH process test no one time keys") {
    //X3DH assumes the files with public key saved in identityKey.key, identityKey.pub

    std::string alice = "alice";
    std::string alice_pwd = "1234";

    C25519KeyGen keyGen; //alice's identity keys
    keyGen.savePrivateKeyPassword(alice + idC25519priv, alice_pwd);
    keyGen.savePublicKey(alice + idC25519pub);

    C25519KeyGen bobIdentity;
    C25519KeyGen bobPreKey;

    C25519 identity;
    identity.setPrivateKey(bobIdentity);

    KeyBundle<C25519> bundle;
    bundle.generateTimeStamp();
    bundle.identityKey = bobIdentity.getPublicKey();
    bundle.preKey = bobPreKey.getPublicKey();
    bundle.preKeySingiture = identity.sign(bundle.preKey);

    SendData toSend{"1.3.2013", "user", {1, 2, 3, 4}};

    X3DH x3dh_alice(alice, alice_pwd);
    //setTimestamp() not needed in x3dh_alice as alice is not using .in()

    X3DHRequest<C25519> request;
    X3DH::X3DHSecretPubKey secret;
    std::tie(request, secret) = x3dh_alice.setSecret(bundle);

    SECTION("SIMULATE receiver") {
        CHECK(secret.sk.size() == 16);
        REQUIRE(request.opKeyUsed == 0x00);

        std::vector <unsigned char> dhs;

        // DH1 step
        C25519 dhcurve;
        dhcurve.setPrivateKey(bobPreKey);
        dhcurve.setPublicKey(request.senderIdPubKey);
        dhs = dhcurve.getShared();

        //DH2 step
        identity.setPublicKey(request.senderEphermalPubKey);
        appendVector(dhs, identity.getShared());

        //DH3
        dhcurve.setPublicKey(request.senderEphermalPubKey);
        appendVector(dhs, dhcurve.getShared());

        hkdf kdf;
        std::string sk = kdf.generate(to_hex(dhs), 16);

        CHECK(sk == to_hex(secret.sk));
    }

    SECTION("ACTUAL receiver current pwdSet") {
        std::string bob = "bob";
        std::string bob_pwd = "bob je svaloun";

        Response r{{Response::Type::RECEIVE, 0, 0}, request.serialize()};

        bobIdentity.savePublicKey(bob + idC25519pub);
        bobIdentity.savePrivateKeyPassword(bob + idC25519priv, bob_pwd);

        bobPreKey.savePublicKey(bob + preC25519pub);
        bobPreKey.savePrivateKeyPassword(bob + preC25519priv, bob_pwd);

        X3DH x3dh_bob(bob, bob_pwd);
        x3dh_bob.setTimestamp(bundle.timestamp);

        std::vector<unsigned char> messageEncrypted;
        X3DH::X3DHSecretKeyPair bob_secret;
        std::tie(messageEncrypted, bob_secret) = x3dh_bob.getSecret(r);
        CHECK(bob_secret.sk == secret.sk);
    }

    SECTION("ACTUAL receiver old pwdSet") {
        std::string bob = "bob";
        std::string bob_pwd = "bob je svaloun";

        Response r{{Response::Type::RECEIVE, 0, 0}, request.serialize()};

        bobIdentity.savePublicKey(bob + idC25519pub + ".old");
        bobIdentity.savePrivateKeyPassword(bob + idC25519priv + ".old", bob_pwd);

        bobPreKey.savePublicKey(bob + preC25519pub + ".old");
        bobPreKey.savePrivateKeyPassword(bob + preC25519priv + ".old", bob_pwd);

        X3DH x3dh_bob(bob, bob_pwd);
        x3dh_bob.setTimestamp(bundle.timestamp + 1); //different timestamp!

        std::vector<unsigned char> messageEncrypted;
        X3DH::X3DHSecretKeyPair bob_secret;
        std::tie(messageEncrypted, bob_secret) = x3dh_bob.getSecret(r);

        CHECK(bob_secret.sk == secret.sk);
    }
}




