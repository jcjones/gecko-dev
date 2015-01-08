/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/*
 * trust_domain.h
 *
 * Implementation of the Mozilla::PKIX TrustDomain using the NSS Certificate DB.
 *
 */


#ifndef mozilla_pkix_nss__trust_domain_h
#define mozilla_pkix_nss__trust_domain_h

#include "pkix/pkix.h"

#include "cert.h"
#include "pkix/ScopedPtr.h"

// XXX Logging
extern PRLogModuleInfo *pkixLog;
#define gCertVerifierLog pkixLog

typedef mozilla::pkix::ScopedPtr<CERTCertificate, CERT_DestroyCertificate>
          ScopedCERTCertificate;
typedef mozilla::pkix::ScopedPtr<CERTCertList, CERT_DestroyCertList>
          ScopedCERTCertList;

namespace nss { namespace mozpkix {

class OCSPCache {}; // XXX
class PinningMode {}; // XXX
class OCSPConfig {}; // XXX

bool CertIsAuthoritativeForEVPolicy(const CERTCertificate* cert,
                                    const mozilla::pkix::CertPolicyId& policy);

class NSSCertDBTrustDomain : public mozilla::pkix::TrustDomain
{
public:
  typedef mozilla::pkix::Result Result;

  enum OCSPFetching {
    NeverFetchOCSP = 0,
    FetchOCSPForDVSoftFail = 1,
    FetchOCSPForDVHardFail = 2,
    FetchOCSPForEV = 3,
    LocalOnlyOCSPForEV = 4,
  };

  NSSCertDBTrustDomain(SECTrustType certDBTrustType, OCSPFetching ocspFetching,
                       OCSPCache& ocspCache, void* pinArg,
                       OCSPConfig ocspConfig,
                       PinningMode pinningMode,
                       bool forEV,
          /*optional*/ const char* hostname = nullptr,
      /*optional out*/ ScopedCERTCertList* builtChain = nullptr);

   virtual Result GetCertTrust(mozilla::pkix::EndEntityOrCA endEntityOrCA,
                               const mozilla::pkix::CertPolicyId& policy,
                               mozilla::pkix::Input candidateCertDER,
                               /*out*/ mozilla::pkix::TrustLevel& trustLevel)
                               override;

   virtual Result FindIssuer(mozilla::pkix::Input encodedIssuerName,
                             IssuerChecker& checker,
                             mozilla::pkix::Time time) override;

   virtual Result IsChainValid(const mozilla::pkix::DERArray& certChain,
                               mozilla::pkix::Time time) override;

   virtual Result CheckRevocation(
                      mozilla::pkix::EndEntityOrCA endEntityOrCA,
                      const mozilla::pkix::CertID& certID,
                      mozilla::pkix::Time time,
         /*optional*/ const mozilla::pkix::Input* stapledOCSPResponse,
         /*optional*/ const mozilla::pkix::Input* aiaExtension)
                      override;

   virtual Result CheckPublicKey(mozilla::pkix::Input subjectPublicKeyInfo)
                                 override;

   virtual Result VerifySignedData(
                      const mozilla::pkix::SignedDataWithSignature& signedData,
                      mozilla::pkix::Input subjectPublicKeyInfo)
                      override;

   virtual Result DigestBuf(mozilla::pkix::Input item,
                            /*out*/ uint8_t* digestBuf,
                            size_t digestBufLen) override;
private:
  enum EncodedResponseSource {
    ResponseIsFromNetwork = 1,
    ResponseWasStapled = 2
  };
  Result VerifyAndMaybeCacheEncodedOCSPResponse(
    const mozilla::pkix::CertID& certID, mozilla::pkix::Time time,
    uint16_t maxLifetimeInDays, mozilla::pkix::Input encodedResponse,
    EncodedResponseSource responseSource, /*out*/ bool& expired);

  const SECTrustType mCertDBTrustType;
  const OCSPFetching mOCSPFetching;
  OCSPCache& mOCSPCache; // non-owning!
  void* mPinArg; // non-owning!
  const OCSPConfig mOCSPConfig;
  PinningMode mPinningMode;
  const unsigned int mMinimumNonECCBits;
  const char* mHostname; // non-owning - only used for pinning checks
  ScopedCERTCertList* mBuiltChain; // non-owning
};


} } // namespace nss::mozpkix

#endif // mozilla_pkix_nss__trust_domain_h
