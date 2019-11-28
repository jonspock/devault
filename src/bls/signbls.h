#pragma once

#include <vector>
#include <key.h>

namespace bls {

    bool SignBLS(const CKey& key, const uint256 &hash, std::vector<uint8_t> &vchSig);
    std::vector<uint8_t> AggregateSigsBLS(std::vector<std::vector<uint8_t>> &vchSig);
    std::vector<uint8_t> AggregatePubKeys(std::vector<std::vector<uint8_t>> &vPubKeys);

} // namespace bls
