/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/*
 * moz_pkix.c
 *
 * Lifecycle Functions for the Mozilla PKIX library.
 *
 */

#import "moz_pkix.h"

#import "pkit.h"
#import "pkix/pkix.h"
#import "trust_domain.h"

void MOZ_PKIX_Initialize() {
  nss::pkix::NSSCertDBTrustDomain trustDomain;
}

PRBool
MOZ_PKIX_GetUseMozPKIXForValidation() {
  return PR_TRUE;
}

SECStatus
MOZ_PKIX_VerifyCertChain(CERTCertificate *cert,
                         PRBool checkSig,
                         SECCertUsage certUsage, PRTime t, void *wincx,
      /* out */          CERTVerifyLog *log,
      /* optional out */ PRBool *sigerror,
      /* optional out */ PRBool *revoked) {

  PR_ASSERT(cert);

  nss::pkix::NSSCertDBTrustDomain trustDomain;
  mozilla::pkix::Result rv;

  if (revoked)
    *revoked = PR_FALSE;
  if (sigerror)
    *sigerror = PR_FALSE;

  /* Convert certificate. */
  mozilla::pkix::Input pkixCert;
  rv = pkixCert.Init(
              static_cast<const uint8_t*>(cert->nssCertificate->encoding.data),
              cert->nssCertificate->encoding.size);
  if (rv != mozilla::pkix::Success) {
    return SECStatus::SECFailure;
  }

  /* Convert timestamp. */
  mozilla::pkix::Time pkixTime = mozilla::pkix::TimeFromEpochInSeconds(t / PR_MSEC_PER_SEC);

  /* TODO: Determine correct key usage, purpose, and policy. */
  rv = mozilla::pkix::BuildCertChain(trustDomain, pkixCert, pkixTime,
        mozilla::pkix::EndEntityOrCA::MustBeEndEntity,
        mozilla::pkix::KeyUsage::noParticularKeyUsageRequired,
        mozilla::pkix::KeyPurposeId::anyExtendedKeyUsage,
        mozilla::pkix::CertPolicyId::anyPolicy,
        nullptr
        );

  printf("rv= %d %s", rv, mozilla::pkix::MapResultToName(rv));

  switch(rv) {
    case mozilla::pkix::Result::ERROR_REVOKED_CERTIFICATE:
      if (revoked)
        *revoked = PR_TRUE;
      break;
    case mozilla::pkix::Result::ERROR_BAD_SIGNATURE:
      if (sigerror)
        *sigerror = PR_TRUE;
      break;
  }

  /* TODO: Append to the CERTVerifyLog. */

  if (rv == mozilla::pkix::Success) {
    return SECStatus::SECSuccess;
  }

  return SECStatus::SECFailure;
}
