/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/dom/U2F.h"
#include "mozilla/dom/U2FBinding.h"
#include "mozilla/dom/CryptoBuffer.h"
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

// Only needed for refcounted objects.
NS_IMPL_CYCLE_COLLECTION_WRAPPERCACHE_0(U2F)
NS_IMPL_CYCLE_COLLECTING_ADDREF(U2F)
NS_IMPL_CYCLE_COLLECTING_RELEASE(U2F)
NS_INTERFACE_MAP_BEGIN_CYCLE_COLLECTION(U2F)
  NS_WRAPPERCACHE_INTERFACE_MAP_ENTRY
  NS_INTERFACE_MAP_ENTRY(nsISupports)
NS_INTERFACE_MAP_END

// XXX: Do these need to actually do something?
U2F::U2F() {}
U2F::~U2F() {}

/* virtual */ JSObject*
U2F::WrapObject(JSContext* aCx, JS::Handle<JSObject*> aGivenProto)
{
  return U2FBinding::Wrap(aCx, this, aGivenProto);
}

void
U2F::Init(nsPIDOMWindow* aParent) {
  mParent = do_QueryInterface(aParent);
  MOZ_ASSERT(mParent);

  // XXX: This feels a little odd.  Can this object ever live
  //      beyond the lifetime of the document?
  // XXX: The chain of arrows feels risky.  Check for nulls
  //      along the way?
  nsCString origin;
  nsresult rv = mParent->GetDoc()->NodePrincipal()->GetOrigin(origin);
  MOZ_ASSERT(NS_SUCCEEDED(rv));
  mOrigin = NS_ConvertUTF8toUTF16(origin);

  rv = mToken.Init();
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

// TODO: Enable sending of error messages
// XXX: Template?
void
RegisterError(U2FRegisterCallback& aCallback,
              ErrorCode aErrorCode)
{
  ErrorResult result;
  RegisterResponse response;
  response.mErrorCode.Construct((uint32_t) aErrorCode);
  aCallback.Call(response, result);
}

void
SignError(U2FSignCallback& aCallback,
          ErrorCode aErrorCode)
{
  ErrorResult result;
  SignResponse response;
  response.mErrorCode.Construct((uint32_t) aErrorCode);
  aCallback.Call(response, result);
}


void
U2F::Register(const Sequence<RegisterRequest>& registerRequests,
              const Sequence<SignRequest>& signRequests,
              U2FRegisterCallback& callback,
              const Optional<Nullable<int32_t>>& opt_timeoutSeconds,
              ErrorResult& aRv)
{
  // Find a registration of appropriate version
  const nsString& tokenVersion = mToken.Version();
  size_t i;
  for (i = 0; i < registerRequests.Length(); i += 1) {
    // Check for version and required attributes
    if (registerRequests[i].mVersion.WasPassed() &&
        registerRequests[i].mVersion.Value() == tokenVersion &&
        registerRequests[i].mChallenge.WasPassed() &&
        registerRequests[i].mAppId.WasPassed()) {
      break;
    }
  }
  if (i >= registerRequests.Length()) {
    RegisterError(callback, ErrorCode::BAD_REQUEST);
    return;
  }
  RegisterRequest request(registerRequests[i]);

  // Verify the asserted appId
  if (!ValidAppID(request.mAppId.Value())) {
    RegisterError(callback, ErrorCode::BAD_REQUEST);
    return;
  }

  // Assemble a clientData object to send back
  // XXX: Not needed until there's attestation
  CryptoBuffer clientData;
  nsresult rv = AssembleClientData(FinishEnrollment,
                                   request.mChallenge.Value(),
                                   clientData);
  if (NS_FAILED(rv)) {
    RegisterError(callback, ErrorCode::OTHER_ERROR);
    return;
  }

  // Get the registration data from the token
  // XXX: Should pass in a challengeParam and appParam
  CryptoBuffer bogus;
  CryptoBuffer registrationData;
  rv = mToken.Register(bogus, bogus, registrationData);
  if (NS_FAILED(rv)) {
    RegisterError(callback, ErrorCode::OTHER_ERROR);
    return;
  }

  // Assemble a response object to return
  nsString clientDataBase64, registrationDataBase64;
  if (NS_FAILED(clientData.ToJwkBase64(clientDataBase64)) ||
      NS_FAILED(registrationData.ToJwkBase64(registrationDataBase64))) {
    RegisterError(callback, ErrorCode::OTHER_ERROR);
    return;
  }
  RegisterResponse response;
  response.mClientData.Construct(clientDataBase64);
  response.mRegistrationData.Construct(registrationDataBase64);
  response.mErrorCode.Construct((uint32_t) ErrorCode::OK);

  ErrorResult result;
  callback.Call(response, result);
}

void
U2F::Sign(const Sequence<SignRequest>& signRequests,
          U2FSignCallback& callback,
          const Optional<Nullable<int32_t>>& opt_timeoutSeconds,
          ErrorResult& aRv)
{
  // Find a registration of appropriate version
  const nsString& tokenVersion = mToken.Version();
  size_t i;
  for (i = 0; i < signRequests.Length(); i += 1) {
    // Check for version and required attributes
    if (signRequests[i].mVersion.WasPassed() &&
        signRequests[i].mVersion.Value() == tokenVersion &&
        signRequests[i].mChallenge.WasPassed() &&
        signRequests[i].mAppId.WasPassed() &&
        signRequests[i].mKeyHandle.WasPassed()) {
      break;
    }
  }
  if (i >= signRequests.Length()) {
    SignError(callback, ErrorCode::BAD_REQUEST);
    return;
  }
  SignRequest request(signRequests[i]);

  // Verify the asserted appId
  if (!ValidAppID(request.mAppId.Value())) {
    SignError(callback, ErrorCode::BAD_REQUEST);
    return;
  }

  // Assemble a clientData object
  CryptoBuffer clientData;
  nsresult rv = AssembleClientData(GetAssertion,
                                   request.mChallenge.Value(),
                                   clientData);
  if (NS_FAILED(rv)) {
    SignError(callback, ErrorCode::OTHER_ERROR);
    return;
  }

  // Digest the appId and the clientData
  // XXX: Assumes that NSS is initialized
  SECStatus srv;
  nsCString appId = NS_ConvertUTF16toUTF8(request.mAppId.Value());
  CryptoBuffer appParam, challengeParam;
  if (!appParam.SetLength(32, fallible) ||
      !challengeParam.SetLength(32, fallible)) {
    SignError(callback, ErrorCode::OTHER_ERROR);
    return;
  }

  srv = PK11_HashBuf(SEC_OID_SHA256, appParam.Elements(),
                     (uint8_t*) appId.BeginReading(), appId.Length());
  if (srv != SECSuccess) {
    SignError(callback, ErrorCode::OTHER_ERROR);
    return;
  }

  srv = PK11_HashBuf(SEC_OID_SHA256, challengeParam.Elements(),
                     clientData.Elements(), clientData.Length());
  if (srv != SECSuccess) {
    SignError(callback, ErrorCode::OTHER_ERROR);
    return;
  }

  // Decode the key handle
  CryptoBuffer keyHandle;
  rv = keyHandle.FromJwkBase64(request.mKeyHandle.Value());
  if (NS_FAILED(rv)) {
    SignError(callback, ErrorCode::OTHER_ERROR);
    return;
  }

  // Get the signature from the token
  CryptoBuffer signatureData;
  rv = mToken.Sign(appParam, challengeParam, keyHandle, signatureData);
  if (NS_FAILED(rv)) {
    SignError(callback, ErrorCode::OTHER_ERROR);
    return;
  }

  // Assemble a response object to return
  nsString clientDataBase64, signatureDataBase64;
  if (NS_FAILED(clientData.ToJwkBase64(clientDataBase64)) ||
      NS_FAILED(signatureData.ToJwkBase64(signatureDataBase64))) {
    SignError(callback, ErrorCode::OTHER_ERROR);
    return;
  }
  SignResponse response;
  response.mKeyHandle.Construct(request.mKeyHandle.Value());
  response.mClientData.Construct(clientDataBase64);
  response.mSignatureData.Construct(signatureDataBase64);
  response.mErrorCode.Construct((uint32_t) ErrorCode::OK);

  ErrorResult result;
  callback.Call(response, result);
}


} // namespace dom
} // namespace mozilla
