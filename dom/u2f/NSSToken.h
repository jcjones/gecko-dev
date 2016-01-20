/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_dom_NSSToken_h
#define mozilla_dom_NSSToken_h

#include "mozilla/dom/CryptoBuffer.h"
#include "mozilla/Mutex.h"
#include "nsNSSShutDown.h"
#include "ScopedNSSTypes.h"

namespace mozilla {
namespace dom {

// NSSToken implements FIDO operations using NSS for the crypto layer.
//
// NOTE: Using this token is NOT SECURE.  Key handles are simply a direct
// encoding of the private key, so they can be used to forge signatures.
class NSSToken final : public nsNSSShutDownObject
{
public:
  NSSToken();

  ~NSSToken() ;

  nsresult Init() ;

  const nsString& Version() const ;

  nsresult Register(const CryptoBuffer& aApplicationParam,
                    const CryptoBuffer& aChallengeParam,
                    CryptoBuffer& aRegistrationData) ;

  nsresult Sign(const CryptoBuffer& aApplicationParam,
                const CryptoBuffer& aChallengeParam,
                const CryptoBuffer& aKeyHandle,
                CryptoBuffer& aSignatureData) ;

  // No NSS resources to release.
  virtual
  void virtualDestroyNSSReference() override {};

private:
  bool mInitialized;
  uint32_t mCounter;
  ScopedPK11SlotInfo mSlot;
  mozilla::Mutex mMutex;

  static const nsString mVersion;
};

} // namespace dom
} // namespace mozilla

#endif // mozilla_dom_NSSToken_h
