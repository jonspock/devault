// Copyright (c) 2019 DeVault developers
// Copyright (c) 2019 Jon Spock

#include <bls/signbls.h>
#include "bls/privatekey.hpp"
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

} // namespace bls
