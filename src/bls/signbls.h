#pragma once

#include <vector>
#include <key.h>

namespace bls {

    bool SignBLS(const CKey& key, const uint256 &hash, std::vector<uint8_t> &vchSig);

} // namespace bls
