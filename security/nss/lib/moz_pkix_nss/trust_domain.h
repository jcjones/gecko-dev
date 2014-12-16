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

#import "pkix/pkix.h"

namespace nss { namespace pkix {

class NSSCertDBTrustDomain : public mozilla::pkix::TrustDomain
{
public:
   typedef mozilla::pkix::Result Result;

   NSSCertDBTrustDomain();

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
};


} } // namespace nss::pkix

#endif // mozilla_pkix_nss__trust_domain_h
