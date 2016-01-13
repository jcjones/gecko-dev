/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/dom/CryptoBuffer.h"
#include "mozilla/dom/U2F.h"
#include "mozilla/dom/U2FBinding.h"
#include "mozilla/Preferences.h"
#include "pk11pub.h"

namespace mozilla {
namespace dom {

enum class ErrorCode {
  OK = 0,
  OTHER_ERROR = 1,
  BAD_REQUEST = 2,
  CONFIGURATION_UNSUPPORTED = 3,
  DEVICE_INELIGIBLE = 4,
  TIMEOUT = 5
};

const nsString
U2F::FinishEnrollment = NS_LITERAL_STRING("navigator.id.finishEnrollment");

const nsString
U2F::GetAssertion = NS_LITERAL_STRING("navigator.id.getAssertion");

// XXX I18N see dom/security/nsCSPUtils.cpp:28
const nsString ERR_NO_TOKENS = NS_LITERAL_STRING("No U2F tokens were available");
const nsString ERR_NO_VERSION = NS_LITERAL_STRING("No requests had the correct version");
const nsString ERR_NO_APP_ID = NS_LITERAL_STRING("No valid App ID found");
const nsString ERR_ASSEMBLE = NS_LITERAL_STRING("Could not assemble client data");
const nsString ERR_REGISTER = NS_LITERAL_STRING("Register failed");
const nsString ERR_SERIALIZE = NS_LITERAL_STRING("Could not serialize output");
const nsString ERR_DESERIALIZE = NS_LITERAL_STRING("Could not deserialize input");
const nsString ERR_SIGN = NS_LITERAL_STRING("Could not sign");
const nsString ERR_MEMORY = NS_LITERAL_STRING("Could not allocate memory");
const nsString ERR_HASH = NS_LITERAL_STRING("Could not perform digest function");

// Only needed for refcounted objects.
NS_IMPL_CYCLE_COLLECTION_WRAPPERCACHE_0(U2F)
NS_IMPL_CYCLE_COLLECTING_ADDREF(U2F)
NS_IMPL_CYCLE_COLLECTING_RELEASE(U2F)
NS_INTERFACE_MAP_BEGIN_CYCLE_COLLECTION(U2F)
  NS_WRAPPERCACHE_INTERFACE_MAP_ENTRY
  NS_INTERFACE_MAP_ENTRY(nsISupports)
NS_INTERFACE_MAP_END

U2F::U2F(): mMutex("U2F::mMutex")
{}

U2F::~U2F(){}

/* virtual */ JSObject*
U2F::WrapObject(JSContext* aCx, JS::Handle<JSObject*> aGivenProto)
{
  return U2FBinding::Wrap(aCx, this, aGivenProto);
}

void
U2F::Init(nsPIDOMWindow* aParent) {
  mParent = do_QueryInterface(aParent);
  MOZ_ASSERT(mParent);

  nsCOMPtr<nsIDocument> doc = mParent->GetDoc();
  MOZ_ASSERT(doc);

  // XXX: This feels a little odd.  Can this object ever live
  //      beyond the lifetime of the document?
  nsCString origin;
  nsresult rv = doc->NodePrincipal()->GetOrigin(origin);
  MOZ_ASSERT(NS_SUCCEEDED(rv));
  mOrigin = NS_ConvertUTF8toUTF16(origin);

  // Always initialize the soft token, in case the user flips the pref
  // during runtime.
  rv = mSoftToken.Init();
  MOZ_ASSERT(NS_SUCCEEDED(rv));

  rv = mUSBToken.Init();
  MOZ_ASSERT(NS_SUCCEEDED(rv));
}

nsresult
U2F::AssembleClientData(const nsString& aTyp,
                        const nsString& aChallenge,
                        CryptoBuffer& aClientData)
{
  ClientData clientDataObject;
  clientDataObject.mTyp.Construct(aTyp);
  clientDataObject.mChallenge.Construct(aChallenge);
  clientDataObject.mOrigin.Construct(mOrigin);

  nsAutoString json;
  if (!clientDataObject.ToJSON(json)) {
    return NS_ERROR_FAILURE;
  }

  uint8_t* result = aClientData.Assign(NS_ConvertUTF16toUTF8(json));
  if (!result) {
    return NS_ERROR_FAILURE;
  }

  return NS_OK;
}

bool
U2F::ValidAppID(const nsString& aAppId)
{
  // TODO implement this check
  return true;
}


template <class CB, class Rsp>
void
SendError(CB& aCallback,
              ErrorCode aErrorCode, nsString aErrorMessage)
{
  ErrorResult result;
  Rsp response;
  response.mErrorCode.Construct((uint32_t) aErrorCode);
  response.mErrorMessage.Construct(aErrorMessage);
  aCallback.Call(response, result);
}

void
U2F::Register(const Sequence<RegisterRequest>& registerRequests,
              const Sequence<SignRequest>& signRequests,
              U2FRegisterCallback& callback,
              const Optional<Nullable<int32_t>>& opt_timeoutSeconds,
              ErrorResult& aRv)
{
  MutexAutoLock lock(mMutex);

  const bool softTokenEnabled =
    Preferences::GetBool("security.webauth.u2f.softtoken");

  const bool usbTokenEnabled =
    Preferences::GetBool("security.webauth.u2f.usbtoken");

  // Search the requests for one a token can fulfill
  size_t i;
  for (i = 0; i < registerRequests.Length(); i += 1) {
    RegisterRequest request(registerRequests[i]);

    // Check for equired attributes
    if (!(request.mVersion.WasPassed() &&
        request.mChallenge.WasPassed() &&
        request.mAppId.WasPassed())) {
      SendError<U2FRegisterCallback, RegisterResponse>(callback, ErrorCode::OTHER_ERROR, ERR_NO_APP_ID);
      continue;
    }

    // TODO: Fail early if there's a verison mismatch?

    // Verify the asserted appId
    if (!ValidAppID(request.mAppId.Value())) {
      SendError<U2FRegisterCallback, RegisterResponse>(callback, ErrorCode::BAD_REQUEST, ERR_NO_APP_ID);
      return;
    }

    // Assemble a clientData object to send back
    // XXX: Not needed until there's attestation
    CryptoBuffer clientData;
    nsresult rv = AssembleClientData(FinishEnrollment,
                                     request.mChallenge.Value(),
                                     clientData);
    if (NS_FAILED(rv)) {
      SendError<U2FRegisterCallback, RegisterResponse>(callback, ErrorCode::OTHER_ERROR, ERR_ASSEMBLE);
      return;
    }

    // Get the registration data from the token
    // XXX: Should pass in a challengeParam and appParam
    CryptoBuffer bogus;
    CryptoBuffer registrationData;
    bool registerSuccess = false;

    if (usbTokenEnabled &&
        (request.mVersion.Value() == mUSBToken.Version())) {
        // not yet implemented; fallthrough
    }

    if (softTokenEnabled &&
        (request.mVersion.Value() == mSoftToken.Version())) {
      if (NS_FAILED(mSoftToken.Register(bogus, bogus, registrationData))) {
        SendError<U2FRegisterCallback, RegisterResponse>(callback, ErrorCode::OTHER_ERROR, ERR_REGISTER);
        return;
      }
      registerSuccess = true;
    }

    if (!registerSuccess) {
      // Try another request
      continue;
    }

    // Assemble a response object to return
    nsString clientDataBase64, registrationDataBase64;
    if (NS_FAILED(clientData.ToJwkBase64(clientDataBase64)) ||
        NS_FAILED(registrationData.ToJwkBase64(registrationDataBase64))) {
      SendError<U2FRegisterCallback, RegisterResponse>(callback, ErrorCode::OTHER_ERROR, ERR_SERIALIZE);
      return;
    }

    RegisterResponse response;
    response.mClientData.Construct(clientDataBase64);
    response.mRegistrationData.Construct(registrationDataBase64);
    response.mErrorCode.Construct((uint32_t) ErrorCode::OK);

    ErrorResult result;
    callback.Call(response, result);
    return;
  }

  // Nothing could satisfy
  SendError<U2FRegisterCallback, RegisterResponse>(callback, ErrorCode::BAD_REQUEST, ERR_NO_VERSION);
  return;
}

void
U2F::Sign(const Sequence<SignRequest>& signRequests,
          U2FSignCallback& callback,
          const Optional<Nullable<int32_t>>& opt_timeoutSeconds,
          ErrorResult& aRv)
{
  MutexAutoLock lock(mMutex);

  const bool softTokenEnabled =
    Preferences::GetBool("security.webauth.u2f.softtoken");

  const bool usbTokenEnabled =
    Preferences::GetBool("security.webauth.u2f.usbtoken");

  // Search the requests for one a token can fulfill
  size_t i;
  for (i = 0; i < signRequests.Length(); i += 1) {
    SignRequest request(signRequests[i]);

    // Check for equired attributes
    if (!(request.mVersion.WasPassed() &&
        request.mChallenge.WasPassed() &&
        request.mAppId.WasPassed() &&
        request.mKeyHandle.WasPassed())) {
      SendError<U2FSignCallback, SignResponse>(callback, ErrorCode::OTHER_ERROR, ERR_NO_APP_ID);
      continue;
    }

    // TODO: Fail early if there's a verison mismatch?

    // Verify the asserted appId
    if (!ValidAppID(request.mAppId.Value())) {
      SendError<U2FSignCallback, SignResponse>(callback, ErrorCode::BAD_REQUEST, ERR_NO_APP_ID);
      return;
    }

    // Assemble a clientData object
    CryptoBuffer clientData;
    nsresult rv = AssembleClientData(GetAssertion,
                                     request.mChallenge.Value(),
                                     clientData);
    if (NS_FAILED(rv)) {
      SendError<U2FSignCallback, SignResponse>(callback, ErrorCode::OTHER_ERROR, ERR_ASSEMBLE);
      return;
    }

    // Digest the appId and the clientData
    // XXX: Assumes that NSS is initialized
    SECStatus srv;
    nsCString appId = NS_ConvertUTF16toUTF8(request.mAppId.Value());
    CryptoBuffer appParam, challengeParam;
    if (!appParam.SetLength(32, fallible) ||
        !challengeParam.SetLength(32, fallible)) {
      SendError<U2FSignCallback, SignResponse>(callback, ErrorCode::OTHER_ERROR, ERR_MEMORY);
      return;
    }

    srv = PK11_HashBuf(SEC_OID_SHA256, appParam.Elements(),
                       (uint8_t*) appId.BeginReading(), appId.Length());
    if (srv != SECSuccess) {
      SendError<U2FSignCallback, SignResponse>(callback, ErrorCode::OTHER_ERROR, ERR_HASH);
      return;
    }

    srv = PK11_HashBuf(SEC_OID_SHA256, challengeParam.Elements(),
                       clientData.Elements(), clientData.Length());
    if (srv != SECSuccess) {
      SendError<U2FSignCallback, SignResponse>(callback, ErrorCode::OTHER_ERROR, ERR_HASH);
      return;
    }

    // Decode the key handle
    CryptoBuffer keyHandle;
    rv = keyHandle.FromJwkBase64(request.mKeyHandle.Value());
    if (NS_FAILED(rv)) {
      SendError<U2FSignCallback, SignResponse>(callback, ErrorCode::OTHER_ERROR, ERR_DESERIALIZE);
      return;
    }

    // Get the signature from the token
    CryptoBuffer signatureData;
    bool signSuccess = false;

    if (usbTokenEnabled &&
        (request.mVersion.Value() == mUSBToken.Version())) {
        // not yet implemented; fallthrough
    }

    if (softTokenEnabled &&
        (request.mVersion.Value() == mSoftToken.Version())) {
      if (NS_FAILED(mSoftToken.Sign(appParam, challengeParam, keyHandle, signatureData))) {
        SendError<U2FSignCallback, SignResponse>(callback, ErrorCode::OTHER_ERROR, ERR_SIGN);
        return;
      }
      signSuccess = true;
    }

    if (!signSuccess) {
      // Try another request
      continue;
    }

    // Assemble a response object to return
    nsString clientDataBase64, signatureDataBase64;
    if (NS_FAILED(clientData.ToJwkBase64(clientDataBase64)) ||
        NS_FAILED(signatureData.ToJwkBase64(signatureDataBase64))) {
      SendError<U2FSignCallback, SignResponse>(callback, ErrorCode::OTHER_ERROR, ERR_SERIALIZE);
      return;
    }
    SignResponse response;
    response.mKeyHandle.Construct(request.mKeyHandle.Value());
    response.mClientData.Construct(clientDataBase64);
    response.mSignatureData.Construct(signatureDataBase64);
    response.mErrorCode.Construct((uint32_t) ErrorCode::OK);

    ErrorResult result;
    callback.Call(response, result);
    return;
  }

  // Nothing could satisfy
  SendError<U2FSignCallback, SignResponse>(callback, ErrorCode::BAD_REQUEST, ERR_NO_VERSION);
  return;
}


} // namespace dom
} // namespace mozilla
