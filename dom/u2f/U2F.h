/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_dom_U2F_h
#define mozilla_dom_U2F_h

#include "js/TypeDecls.h"
#include "mozilla/Attributes.h"
#include "mozilla/dom/BindingDeclarations.h"
#include "mozilla/dom/Nullable.h"
#include "mozilla/ErrorResult.h"
#include "nsCycleCollectionParticipant.h"
#include "nsPIDOMWindow.h"
#include "nsWrapperCache.h"

#include "NSSToken.h"
#include "USBToken.h"

namespace mozilla {
namespace dom {

struct RegisterRequest;
struct SignRequest;
class U2FRegisterCallback;
class U2FSignCallback;

} // namespace dom
} // namespace mozilla

namespace mozilla {
namespace dom {

class U2F final : public nsISupports,
                  public nsWrapperCache
{
protected:
  ~U2F();

public:
  NS_DECL_CYCLE_COLLECTING_ISUPPORTS
  NS_DECL_CYCLE_COLLECTION_SCRIPT_HOLDER_CLASS(U2F)

  U2F();

  nsPIDOMWindow*
  GetParentObject() const
  {
    return mParent;
  }

  void
  Init(nsPIDOMWindow* aParent);

  virtual JSObject*
  WrapObject(JSContext* aCx, JS::Handle<JSObject*> aGivenProto) override;

  void
  Register(const Sequence<RegisterRequest>& registerRequests,
           const Sequence<SignRequest>& signRequests,
           U2FRegisterCallback& callback,
           const Optional<Nullable<int32_t>>& opt_timeoutSeconds,
           ErrorResult& aRv);

  void
  Sign(const Sequence<SignRequest>& signRequests,
       U2FSignCallback& callback,
       const Optional<Nullable<int32_t>>& opt_timeoutSeconds,
       ErrorResult& aRv);

private:
  nsCOMPtr<nsPIDOMWindow> mParent;
  nsString mOrigin;
  NSSToken mSoftToken;
  USBToken mUSBToken;

  static const nsString FinishEnrollment;
  static const nsString GetAssertion;

  nsresult
  AssembleClientData(const nsString& aTyp,
                     const nsString& aChallenge,
                     CryptoBuffer& aClientData);

  bool
  ValidAppID(nsString& aAppId);
};

} // namespace dom
} // namespace mozilla

#endif // mozilla_dom_U2F_h
