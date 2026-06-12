// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2024 Second State INC

//===-- wasmedge/plugins/wasi_crypto/common/secrets_manager.h -------------===//
//
// Part of the WasmEdge Project.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains the Secrets Manager class definition.
///
//===----------------------------------------------------------------------===//

#pragma once

#include "asymmetric_common/keypair.h"
#include "symmetric/key.h"
#include "utils/error.h"
#include "wasi_crypto/api.hpp"

#include <map>
#include <mutex>
#include <shared_mutex>
#include <vector>

namespace WasmEdge {
namespace Host {
namespace WasiCrypto {
namespace Common {

class SecretsManager {
public:
  WasiCryptoExpect<void> invalidate(Span<const uint8_t> KeyId,
                                    __wasi_version_t Version) noexcept {
    std::unique_lock Lock(Mutex);
    KeyIdentifier Ident{std::vector<uint8_t>(KeyId.begin(), KeyId.end()),
                        Version};
    if (KeyPairs.erase(Ident) == 0 && SymmetricKeys.erase(Ident) == 0) {
      return WasiCryptoUnexpect(__WASI_CRYPTO_ERRNO_NOT_FOUND);
    }
    return {};
  }

  WasiCryptoExpect<void> storeKp(Span<const uint8_t> KeyId,
                                 __wasi_version_t Version,
                                 const AsymmetricCommon::KpVariant &Kp) noexcept {
    std::unique_lock Lock(Mutex);
    KeyIdentifier Ident{std::vector<uint8_t>(KeyId.begin(), KeyId.end()),
                        Version};
    KeyPairs[Ident] = Kp;
    return {};
  }

  WasiCryptoExpect<void> storeSk(Span<const uint8_t> KeyId,
                                 __wasi_version_t Version,
                                 const Symmetric::KeyVariant &Sk) noexcept {
    std::unique_lock Lock(Mutex);
    KeyIdentifier Ident{std::vector<uint8_t>(KeyId.begin(), KeyId.end()),
                        Version};
    SymmetricKeys[Ident] = Sk;
    return {};
  }

  WasiCryptoExpect<AsymmetricCommon::KpVariant>
  getKp(Span<const uint8_t> KeyId, __wasi_version_t Version) noexcept {
    std::shared_lock Lock(Mutex);
    KeyIdentifier Ident{std::vector<uint8_t>(KeyId.begin(), KeyId.end()),
                        Version};
    auto It = KeyPairs.find(Ident);
    if (It == KeyPairs.end()) {
      return WasiCryptoUnexpect(__WASI_CRYPTO_ERRNO_NOT_FOUND);
    }
    return It->second;
  }

  WasiCryptoExpect<Symmetric::KeyVariant>
  getSk(Span<const uint8_t> KeyId, __wasi_version_t Version) noexcept {
    std::shared_lock Lock(Mutex);
    KeyIdentifier Ident{std::vector<uint8_t>(KeyId.begin(), KeyId.end()),
                        Version};
    auto It = SymmetricKeys.find(Ident);
    if (It == SymmetricKeys.end()) {
      return WasiCryptoUnexpect(__WASI_CRYPTO_ERRNO_NOT_FOUND);
    }
    return It->second;
  }

private:
  struct KeyIdentifier {
    std::vector<uint8_t> Id;
    __wasi_version_t Version;
    bool operator<(const KeyIdentifier &Rhs) const {
      if (Version != Rhs.Version) {
        return Version < Rhs.Version;
      }
      return Id < Rhs.Id;
    }
  };

  std::map<KeyIdentifier, AsymmetricCommon::KpVariant> KeyPairs;
  std::map<KeyIdentifier, Symmetric::KeyVariant> SymmetricKeys;
  std::shared_mutex Mutex;
};

} // namespace Common
} // namespace WasiCrypto
} // namespace Host
} // namespace WasmEdge
