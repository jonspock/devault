#pragma once
#include <uint256.h>

/** A reference to a CKey: the Hash160 of its serialized public key */
template <int T_=0> class CKeyID : public uint160 {
public:
    CKeyID<T_>() : uint160() {}
    explicit CKeyID<T_>(const uint160 &in) : uint160(in) {}
};
