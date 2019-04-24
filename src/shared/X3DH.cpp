#include "X3DH.h"
#include "utils.h"

namespace helloworld {

std::pair<std::vector<unsigned char>, X3DH::X3DHSecretKeyPair> X3DH::getSecret(const std::vector<unsigned char> &payload, helloworld::Response::Type type) {
    X3DHRequest <C25519> x3dhBundle =
            X3DHRequest<C25519>::deserialize(payload);

    bool old = timestamp != x3dhBundle.timestamp;

    std::vector<unsigned char> dh_bytes;

    C25519 identityKeyCurve;
    identityKeyCurve.loadPrivateKey(
            username + idC25519priv + (old ? ".old" : ""), pwd);
    C25519 preKeyCurve;
    preKeyCurve.loadPrivateKey(
            username + preC25519priv + (old ? ".old" : ""), pwd);

    // DH1 step
    preKeyCurve.setPublicKey(x3dhBundle.senderIdPubKey);
    dh_bytes = preKeyCurve.getShared();

    // DH2 step
    identityKeyCurve.setPublicKey(x3dhBundle.senderEphermalPubKey);
    append(dh_bytes, identityKeyCurve.getShared());

    // DH3 step
    preKeyCurve.setPublicKey(x3dhBundle.senderEphermalPubKey);
    append(dh_bytes, preKeyCurve.getShared());

    // DH4 step
    if (x3dhBundle.opKeyUsed == X3DHRequest<C25519>::OP_KEY_USED) {
        C25519 onetimeKeyCurve;
        onetimeKeyCurve.loadPrivateKey(
                username + std::to_string(x3dhBundle.opKeyId) +
                oneTimeC25519priv + (old ? ".old" : ""),
                pwd);
        onetimeKeyCurve.setPublicKey(x3dhBundle.senderEphermalPubKey);
        append(dh_bytes, onetimeKeyCurve.getShared());
    }

    hkdf kdf;
    std::string sk = kdf.generate(to_hex(dh_bytes), 16);

    std::vector<unsigned char> ad = x3dhBundle.senderIdPubKey;
    append(ad, loadC25519Key(username + idC25519pub + (old ? ".old" : "")));
    std::vector<unsigned char> result;
    auto pubKey = loadC25519Key(username + preC25519pub + (old ? ".old" : ""));

    if (type == Response::Type::RECEIVE_OLD)
        throw Error("RECEIVE_OLD");
    return std::make_pair(x3dhBundle.AEADenrypted,
                          X3DHSecretKeyPair{from_hex(sk), std::move(ad), std::move(pubKey),
                                            preKeyCurve.getPrivateKey()});
}

std::pair<X3DHRequest<C25519>, X3DH::X3DHSecretPubKey> X3DH::setSecret(
        const KeyBundle <C25519> &bundle) const {
    if (!verifyPrekey(bundle.identityKey, bundle.preKey,
                      bundle.preKeySingiture))
        throw Error("X3DH: Key verification has failed.");

    bool opAvailable = !bundle.oneTimeKeys.empty();
    size_t keyId = 0;

    C25519KeyGen ephermalGen;
    // DH1 step
    C25519 identity;
    identity.loadPrivateKey(username + idC25519priv, pwd);
    identity.setPublicKey(bundle.preKey);
    std::vector<unsigned char> dh = identity.getShared();
    // DH2 step
    C25519 ephermal;
    ephermal.setPrivateKey(ephermalGen);
    ephermal.setPublicKey(bundle.identityKey);
    append(dh, ephermal.getShared());
    // DH3 step
    ephermal.setPublicKey(bundle.preKey);
    append(dh, ephermal.getShared());
    // optional DH4 step
    if (opAvailable) {
        keyId = bundle.oneTimeKeys.size() - 1;
        ephermal.setPublicKey(bundle.oneTimeKeys[keyId]);
        append(dh, ephermal.getShared());
    }

    hkdf kdf;
    std::string sk = kdf.generate(to_hex(dh), 16);

    clear<unsigned char>(dh.data(), dh.size());

    std::vector<unsigned char> pubKey = loadC25519Key(username + idC25519pub);

    // build request
    X3DHRequest <C25519> toFill;
    toFill.timestamp = bundle.timestamp;
    toFill.senderIdPubKey = pubKey;
    toFill.senderEphermalPubKey = std::move(ephermalGen.getPublicKey());
    toFill.opKeyUsed = opAvailable ? X3DHRequest<C25519>::OP_KEY_USED
                                   : X3DHRequest<C25519>::OP_KEY_NONE,
            toFill.opKeyId = keyId;

    append(pubKey, bundle.identityKey); //X3DH additional data
    return std::make_pair(toFill, X3DHSecretPubKey{from_hex(sk), pubKey, bundle.preKey});
}

bool X3DH::verifyPrekey(const KeyBundle<C25519>::key_t &identityPub,
                        const KeyBundle<C25519>::key_t &prekeyPub,
                        const KeyBundle<C25519>::signiture_t &signature) const {
    C25519 c;
    // todo X3DH:: encode key signature...? but it won't work
    c.setPublicKey(identityPub);
    return c.verify(signature, prekeyPub);
}

void X3DH::append(std::vector<unsigned char> &to,
                  const std::vector<unsigned char> &from) const {
    to.insert(to.end(), from.begin(), from.end());
}

std::vector<unsigned char> X3DH::loadC25519Key(
        const std::string &filename) const {
    std::ifstream input{filename, std::ios::in | std::ios::binary};
    if (!input) throw Error("Could not load user public key.");
    std::vector<unsigned char> key(C25519::KEY_BYTES_LEN);
    read_n(input, key.data(), key.size());
    return key;
}

} //namespace helloworld
