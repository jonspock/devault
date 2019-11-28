// Copyright (c) 2019 DeVault developers
// Copyright (c) 2019 Jon Spock

#include <bls/signbls.h>
#include "bls/privatekey.hpp"
#include "bls/signature.hpp"
#include "uint256.h"

namespace bls {

    bool SignBLS(const CKey& key, const uint256 &hash, std::vector<uint8_t> &vchSig) {
        auto PK = bls::PrivateKey::FromSeed(key.begin(), PrivateKey::PRIVATE_KEY_SIZE);
        bls::Signature sig = PK.SignPrehashed(hash.begin());
        uint8_t sigBytes[bls::Signature::SIGNATURE_SIZE]; // 96 byte array
        sig.Serialize(sigBytes);
        vchSig.resize(bls::Signature::SIGNATURE_SIZE);
        for (size_t i = 0; i < bls::Signature::SIGNATURE_SIZE; i++) vchSig[i] = sigBytes[i];
        // Then Verify
        return sig.Verify();
    }

    // Convert from std::vector<uint8_t> , aggregate and convert back
    std::vector<uint8_t> AggregateSigsBLS(std::vector<std::vector<uint8_t>> &vchSigs) {

        std::vector<Signature> sigs;
        for (size_t i=0;i<vchSigs.size();i++) {
            Signature sig = Signature::FromBytes(vchSigs[i].data());
            sigs.push_back(sig);
        }

        Signature aggSig = Signature::AggregateSigs(sigs);
        return aggSig.Serialize();
    }

    // Convert from std::vector<uint8_t> , aggregate and convert back
    std::vector<uint8_t> AggregatePubKeys(std::vector<std::vector<uint8_t>> &vPubKeys) {

        std::vector<bls::PublicKey> pubkeys;
        for (size_t i=0;i<vPubKeys.size();i++) {
            bls::PublicKey p = bls::PublicKey::FromBytes(vPubKeys[i].data()); // check
            pubkeys.push_back(p);
        }

        bls::PublicKey aggPubKey = bls::PublicKey::Aggregate(pubkeys);
        return aggPubKey.Serialize();
    }

} // namespace bls
