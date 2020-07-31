// Copyright (c) 2019 DeVault developers
// Copyright (c) 2019 Jon Spock
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bls/bls384_256.h"
#include "bls/bls_functions.h"
#include "util/strencodings.h"
#include <cstring>

namespace bls {

CKey GetBLSPrivateKey(const uint8_t *seed, size_t seedLen, uint32_t childIndex) {
  /*
  PrivateKey master = PrivateKey::FromSeed(seed, seedLen);
  PrivateKey child = HDKeys::DeriveChildSk(master, childIndex);
  auto calculatedChild = child.Serialize();
  */
  CKey k;
  //  k.Set(calculatedChild.begin(),calculatedChild.end());
  return k;
}
  
CKey GetBLSChild(const CKey& key, uint32_t childIndex) {
  /*
  PrivateKey master = PrivateKey::FromBytes(key.begin());
  PrivateKey child = HDKeys::DeriveChildSk(master, childIndex);
  auto calculatedChild = child.Serialize();
  */
  CKey k;
  //k.Set(calculatedChild.begin(),calculatedChild.end());
  return k;
}
  
CKey GetBLSMasterKey(const uint8_t *seed, size_t seedLen) {
  /*
  PrivateKey master = PrivateKey::FromSeed(seed, seedLen);
  auto bytes = master.Serialize();
  */
  CKey k;
  //k.Set(bytes.begin(),bytes.end());
  return k;
}


bool CheckValidBLSPrivateKey(const uint8_t* bytes) {
  blsSecretKey sec;
  if (blsSecretKeyDeserialize(&sec, bytes, 32)) return true;
  else return false;
}
  
bool SignBLS(const CKey &key, const uint256 &hash, std::vector<uint8_t> &vchSig) {
  blsSecretKey sec;
  blsSignature sig;
  if (!blsSecretKeyDeserialize(&sec, key.begin(), 32)) return false;
  std::vector<uint8_t> message(hash.begin(),hash.end());
  blsSign(&sig, &sec, &message[0], message.size());
  blsSignatureDeserialize(&sig, &vchSig[0], 96);
  return true; // for now True - sig.Verify();
}
bool SignBLS(const CKey& key, const std::vector<uint8_t> &message, std::vector<uint8_t> &vchSig) {
  blsSecretKey sec;
  blsSignature sig;
  if (!blsSecretKeyDeserialize(&sec, key.begin(), 32)) return false;
  blsSign(&sig, &sec, &message[0], message.size());
  blsSignatureDeserialize(&sig, &vchSig[0], 96);
  return true; // for now True - sig.Verify();
}
  
bool VerifyBLS(const uint256 &hash, const std::vector<uint8_t> &vchSig, const uint8_t *vch) {
  blsPublicKey pub;
  blsSignature sig;
  blsSignatureDeserialize(&sig, &vchSig[0], 96);
  blsPublicKeyDeserialize(&pub, vch, 48);
  std::vector<uint8_t> message(hash.begin(),hash.end());
  return blsVerify(&sig, &pub, &message[0], message.size());
}

CPubKey GetBLSPublicKey(const CKey &key) {
  blsSecretKey sec;
  blsPublicKey pub;
  std::vector<uint8_t> pubkey(48);
  if (!blsSecretKeyDeserialize(&sec, key.begin(), 32))
    throw std::runtime_error("Problem creating bls private key");
  blsGetPublicKey(&pub, &sec);
  blsPublicKeySerialize(&pubkey[0], 48, &pub);
  CPubKey k(pubkey);
  return k;
}

std::vector<uint8_t> Aggregate(std::vector<std::vector<uint8_t>> &vSigs) {
  blsSignature aggSig;
  std::vector<blsSignature> sigs;
  for (size_t i = 0; i < vSigs.size(); i++) blsSignatureDeserialize(&sigs[i], &vSigs[i], 96);
  blsAggregateSignature(&aggSig, &sigs[0], vSigs.size());
  std::vector<uint8_t> asig(96);
  blsSignatureSerialize(&asig[0], 96, &aggSig);
  return asig;
}

  
//--------------------------------------------------------------------------------------------------
// Convert from std::vector<uint8_t> , aggregate and convert back
/*
std::vector<uint8_t> AggregatePubKeys(std::vector<std::vector<uint8_t>> &vPubKeys) {
  if (vPubKeys.size() == 1) return vPubKeys[0];
  std::vector<bls::PublicKey> pubkeys;
  for (size_t i = 0; i < vPubKeys.size(); i++) {
    bls::PublicKey p = bls::PublicKey::FromBytes(vPubKeys[i].data()); // check
    pubkeys.push_back(p);
  }

  bls::PublicKey aggPubKey = bls::PublicKey::Aggregate(pubkeys);
  return aggPubKey.Serialize();
}
 */

// aggregate and convert to std::vector<uint8_t>
std::vector<uint8_t> AggregateSigForMessages(std::map<uint256, CKey> &keys_plus_hash) {
  bool sigsok = true;
  std::vector<blsSignature> sigs;
  for (const auto &kph : keys_plus_hash) {
    blsSecretKey sec;
    blsSignature sig;
    if (!blsSecretKeyDeserialize(&sec, kph.second.begin(), 32)) sigsok = false;
    std::vector<uint8_t> message(kph.first.begin(),kph.first.end());
    blsSign(&sig, &sec, &message[0], message.size());
    sigs.push_back(sig);
  }
  if (!sigsok) return std::vector<uint8_t>();
  blsSignature aggSigs;
  blsAggregateSignature(&aggSigs, &sigs[0], sigs.size());
  std::vector<uint8_t> asig(96);
  blsSignatureSerialize(&asig[0], 96, &aggSigs);
  return asig;
}

  
bool VerifySigForMessages(const std::vector<uint256> &msgs, const std::vector<uint8_t> &aggSigs,
                          const std::vector<std::vector<uint8_t>> &pubkeys) {

  std::vector<uint8_t> messages;
  for (const auto& m : msgs) {
    std::vector<uint8_t> ms(m.begin(),m.end());
    for (const auto& mm : m) messages.push_back(mm);
  }
  return VerifySigForMessages(messages, aggSigs, pubkeys);
}
  
bool VerifySigForMessages(const std::vector<uint8_t> &msgs, const std::vector<uint8_t> &aggSigs,
                          const std::vector<std::vector<uint8_t>> &pubkeys) {

  std::vector<blsPublicKey> keys;
  blsSignature sig;
  blsSignatureDeserialize(&sig, &aggSigs[0], 96);
  
  for (const auto& p : pubkeys) {
    blsPublicKey pub;
    blsPublicKeyDeserialize(&pub, &p, 48);
    keys.push_back(pub);
  }

  return blsAggregateVerifyNoCheck(
                                   &sig,
                                   &keys[0],
                                   &msgs[0],
                                   msgs.size(),
                                   keys.size());
}
    
} // namespace bls
