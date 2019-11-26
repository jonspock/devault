// Copyright 2018 Chia Network Inc
// Copyright (c) 2019 DeVault developers
// Copyright (c) 2019 Jon Spock

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
#include <bls/getblspublickey.h>

#include "bls/bls.hpp"
#include <cstring>

CPubKey GetBLSPublicKey(const CKey &key) {
    bls::BLS::AssertInitialized();
    bls::PrivateKey priv;
    try {
        priv = bls::PrivateKey::FromSeed(key.begin(), bls::PrivateKey::PRIVATE_KEY_SIZE);
    } catch (...) { throw std::runtime_error("Problem creating bls private key"); }
    try {
        // Get PublicKey and then Serialize bytes to CPubKey 
        bls::PublicKey pub = priv.GetPublicKey();
        auto b = pub.Serialize();
        CPubKey k(b);
        return k;
    } catch (...) { throw std::runtime_error("Problem creating bls public key"); }
    return (CPubKey());
}

