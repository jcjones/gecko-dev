/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/*
 * trust_domain.cc
 *
 * Implementation of the Mozilla::PKIX TrustDomain using the NSS Certificate DB.
 *
 */

#include "trust_domain.h"

using namespace mozilla;
using namespace mozilla::pkix;

namespace nss { namespace pkix {

NSSCertDBTrustDomain::NSSCertDBTrustDomain()
{

}

Result
NSSCertDBTrustDomain::GetCertTrust(EndEntityOrCA endEntityOrCA,
                                   const CertPolicyId& policy,
                                   Input candidateCertDER,
                                   /*out*/ TrustLevel& trustLevel)
{
  return Result::FATAL_ERROR_LIBRARY_FAILURE;
}


Result
NSSCertDBTrustDomain::FindIssuer(mozilla::pkix::Input encodedIssuerName,
                             mozilla::pkix::TrustDomain::IssuerChecker& checker,
                             mozilla::pkix::Time time)
{
  return Result::FATAL_ERROR_LIBRARY_FAILURE;
}

Result
NSSCertDBTrustDomain::IsChainValid(const mozilla::pkix::DERArray& certChain,
                               mozilla::pkix::Time time)
{
  return Result::FATAL_ERROR_LIBRARY_FAILURE;
}

Result
NSSCertDBTrustDomain::CheckRevocation(
                      mozilla::pkix::EndEntityOrCA endEntityOrCA,
                      const mozilla::pkix::CertID& certID,
                      mozilla::pkix::Time time,
         /*optional*/ const mozilla::pkix::Input* stapledOCSPResponse,
         /*optional*/ const mozilla::pkix::Input* aiaExtension)
{
  return Result::FATAL_ERROR_LIBRARY_FAILURE;
}

Result
NSSCertDBTrustDomain::CheckPublicKey(mozilla::pkix::Input subjectPublicKeyInfo)
{
  return Result::FATAL_ERROR_LIBRARY_FAILURE;
}

Result
NSSCertDBTrustDomain::VerifySignedData(
                      const mozilla::pkix::SignedDataWithSignature& signedData,
                      mozilla::pkix::Input subjectPublicKeyInfo)
{
  return Result::FATAL_ERROR_LIBRARY_FAILURE;
}

Result
NSSCertDBTrustDomain::DigestBuf(mozilla::pkix::Input item,
                            /*out*/ uint8_t* digestBuf,
                            size_t digestBufLen)
{
  return Result::FATAL_ERROR_LIBRARY_FAILURE;
}

} } // namespace nss::pkix
