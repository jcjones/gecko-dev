/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "USBToken.h"

namespace mozilla {
namespace dom {

USBToken::USBToken()
  : mInitialized(false)
{}

USBToken::~USBToken()
{}

nsresult
USBToken::Init()
{
  if (mInitialized) {
    return NS_OK;
  }

  mInitialized = true;
  return NS_OK;
}

const nsString USBToken::mVersion = NS_LITERAL_STRING("U2F_V2");

const nsString&
USBToken::Version() const
{
  return mVersion;
}

nsresult
USBToken::Register(const CryptoBuffer& /* aChallengeParam */,
                   const CryptoBuffer& /* aApplicationParam */,
                   CryptoBuffer& aRegistrationData) const
{
  return NS_ERROR_NOT_AVAILABLE;
}

nsresult
USBToken::Sign(const CryptoBuffer& aApplicationParam,
               const CryptoBuffer& aChallengeParam,
               const CryptoBuffer& aKeyHandle,
               CryptoBuffer& aSignatureData)
{
  return NS_ERROR_NOT_AVAILABLE;
}

} // namespace dom
} // namespace mozilla
