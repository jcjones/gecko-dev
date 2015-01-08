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

#include "pkit.h"
#include "certdb.h"
#include "pkixnss.h"

using namespace mozilla;
using namespace mozilla::pkix;

static const uint64_t ServerFailureDelaySeconds = 5 * 60;

static const unsigned int MINIMUM_NON_ECC_BITS_DV = 1024;
static const unsigned int MINIMUM_NON_ECC_BITS_EV = 2048;

namespace nss { namespace mozpkix {

bool CertIsAuthoritativeForEVPolicy(const CERTCertificate* cert,
                                    const mozilla::pkix::CertPolicyId& policy) {
  return false; // XXX
}

NSSCertDBTrustDomain::NSSCertDBTrustDomain(SECTrustType certDBTrustType,
                                           OCSPFetching ocspFetching,
                                           OCSPCache& ocspCache,
             /*optional but shouldn't be*/ void* pinArg,
                                           OCSPConfig ocspConfig,
                                           PinningMode pinningMode,                                           bool forEV,
                              /*optional*/ const char* hostname,
                              /*optional*/ ScopedCERTCertList* builtChain)
  : mCertDBTrustType(certDBTrustType)
  , mOCSPFetching(ocspFetching)
  , mOCSPCache(ocspCache)
  , mPinArg(pinArg)
  , mOCSPConfig(ocspConfig)
  , mPinningMode(pinningMode)
  , mMinimumNonECCBits(forEV ? MINIMUM_NON_ECC_BITS_EV : MINIMUM_NON_ECC_BITS_DV)
  , mHostname(hostname)
  , mBuiltChain(builtChain)
{
}

Result
NSSCertDBTrustDomain::GetCertTrust(EndEntityOrCA endEntityOrCA,
                                   const CertPolicyId& policy,
                                   Input candidateCertDER,
                                   /*out*/ TrustLevel& trustLevel)
{
#ifdef MOZ_NO_EV_CERTS
  if (!policy.IsAnyPolicy()) {
    return Result::ERROR_POLICY_VALIDATION_FAILED;
  }
#endif

  // XXX: This would be cleaner and more efficient if we could get the trust
  // information without constructing a CERTCertificate here, but NSS doesn't
  // expose it in any other easy-to-use fashion. The use of
  // CERT_NewTempCertificate to get a CERTCertificate shouldn't be a
  // performance problem because NSS will just find the existing
  // CERTCertificate in its in-memory cache and return it.
  SECItem candidateCertDERSECItem = UnsafeMapInputToSECItem(candidateCertDER);
  ScopedCERTCertificate candidateCert(
    CERT_NewTempCertificate(CERT_GetDefaultCertDB(), &candidateCertDERSECItem,
                            nullptr, false, true));
  if (!candidateCert) {
    return MapPRErrorCodeToResult(PR_GetError());
  }

  // XXX: CERT_GetCertTrust seems to be abusing SECStatus as a boolean, where
  // SECSuccess means that there is a trust record and SECFailure means there
  // is not a trust record. I looked at NSS's internal uses of
  // CERT_GetCertTrust, and all that code uses the result as a boolean meaning
  // "We have a trust record."
  CERTCertTrust trust;
  if (CERT_GetCertTrust(candidateCert.get(), &trust) == SECSuccess) {
    uint32_t flags = SEC_GET_TRUST_FLAGS(&trust, mCertDBTrustType);

    // For DISTRUST, we use the CERTDB_TRUSTED or CERTDB_TRUSTED_CA bit,
    // because we can have active distrust for either type of cert. Note that
    // CERTDB_TERMINAL_RECORD means "stop trying to inherit trust" so if the
    // relevant trust bit isn't set then that means the cert must be considered
    // distrusted.
    uint32_t relevantTrustBit =
      endEntityOrCA == EndEntityOrCA::MustBeCA ? CERTDB_TRUSTED_CA
                                               : CERTDB_TRUSTED;
    if (((flags & (relevantTrustBit|CERTDB_TERMINAL_RECORD)))
            == CERTDB_TERMINAL_RECORD) {
      trustLevel = TrustLevel::ActivelyDistrusted;
      return Success;
    }

    // For TRUST, we only use the CERTDB_TRUSTED_CA bit, because Gecko hasn't
    // needed to consider end-entity certs to be their own trust anchors since
    // Gecko implemented nsICertOverrideService.
    if (flags & CERTDB_TRUSTED_CA) {
      if (policy.IsAnyPolicy()) {
        trustLevel = TrustLevel::TrustAnchor;
        return Success;
      }
#ifndef MOZ_NO_EV_CERTS
      if (CertIsAuthoritativeForEVPolicy(candidateCert.get(), policy)) {
        trustLevel = TrustLevel::TrustAnchor;
        return Success;
      }
#endif
    }
  }

  trustLevel = TrustLevel::InheritsTrust;
  return Success;
}

// E=igca@sgdn.pm.gouv.fr,CN=IGC/A,OU=DCSSI,O=PM/SGDN,L=Paris,ST=France,C=FR
static const uint8_t ANSSI_SUBJECT_DATA[] =
                       "\x30\x81\x85\x31\x0B\x30\x09\x06\x03\x55\x04"
                       "\x06\x13\x02\x46\x52\x31\x0F\x30\x0D\x06\x03"
                       "\x55\x04\x08\x13\x06\x46\x72\x61\x6E\x63\x65"
                       "\x31\x0E\x30\x0C\x06\x03\x55\x04\x07\x13\x05"
                       "\x50\x61\x72\x69\x73\x31\x10\x30\x0E\x06\x03"
                       "\x55\x04\x0A\x13\x07\x50\x4D\x2F\x53\x47\x44"
                       "\x4E\x31\x0E\x30\x0C\x06\x03\x55\x04\x0B\x13"
                       "\x05\x44\x43\x53\x53\x49\x31\x0E\x30\x0C\x06"
                       "\x03\x55\x04\x03\x13\x05\x49\x47\x43\x2F\x41"
                       "\x31\x23\x30\x21\x06\x09\x2A\x86\x48\x86\xF7"
                       "\x0D\x01\x09\x01\x16\x14\x69\x67\x63\x61\x40"
                       "\x73\x67\x64\x6E\x2E\x70\x6D\x2E\x67\x6F\x75"
                       "\x76\x2E\x66\x72";

static const uint8_t PERMIT_FRANCE_GOV_NAME_CONSTRAINTS_DATA[] =
                       "\x30\x5D" // SEQUENCE (length=93)
                       "\xA0\x5B" // permittedSubtrees (length=91)
                       "\x30\x05\x82\x03" ".fr"
                       "\x30\x05\x82\x03" ".gp"
                       "\x30\x05\x82\x03" ".gf"
                       "\x30\x05\x82\x03" ".mq"
                       "\x30\x05\x82\x03" ".re"
                       "\x30\x05\x82\x03" ".yt"
                       "\x30\x05\x82\x03" ".pm"
                       "\x30\x05\x82\x03" ".bl"
                       "\x30\x05\x82\x03" ".mf"
                       "\x30\x05\x82\x03" ".wf"
                       "\x30\x05\x82\x03" ".pf"
                       "\x30\x05\x82\x03" ".nc"
                       "\x30\x05\x82\x03" ".tf";


Result
NSSCertDBTrustDomain::FindIssuer(mozilla::pkix::Input encodedIssuerName,
                             mozilla::pkix::TrustDomain::IssuerChecker& checker,
                             mozilla::pkix::Time time)
{
  // TODO: NSS seems to be ambiguous between "no potential issuers found" and
  // "there was an error trying to retrieve the potential issuers."
  SECItem encodedIssuerNameSECItem = UnsafeMapInputToSECItem(encodedIssuerName);
  ScopedCERTCertList
    candidates(CERT_CreateSubjectCertList(nullptr, CERT_GetDefaultCertDB(),
                                          &encodedIssuerNameSECItem, 0,
                                          false));
  if (candidates) {
    for (CERTCertListNode* n = CERT_LIST_HEAD(candidates);
         !CERT_LIST_END(n, candidates); n = CERT_LIST_NEXT(n)) {
      Input certDER;
      Result rv = certDER.Init(n->cert->derCert.data, n->cert->derCert.len);
      if (rv != Success) {
        continue; // probably too big
      }

      bool keepGoing;
      Input anssiSubject;
      rv = anssiSubject.Init(ANSSI_SUBJECT_DATA,
                             sizeof(ANSSI_SUBJECT_DATA) - 1);
      if (rv != Success) {
        return Result::FATAL_ERROR_LIBRARY_FAILURE;
      }
      // TODO: Use CERT_CompareName or equivalent
      if (InputsAreEqual(encodedIssuerName, anssiSubject)) {
        Input anssiNameConstraints;
        if (anssiNameConstraints.Init(
                PERMIT_FRANCE_GOV_NAME_CONSTRAINTS_DATA,
                sizeof(PERMIT_FRANCE_GOV_NAME_CONSTRAINTS_DATA) - 1)
              != Success) {
          return Result::FATAL_ERROR_LIBRARY_FAILURE;
        }
        rv = checker.Check(certDER, &anssiNameConstraints, keepGoing);
      } else {
        rv = checker.Check(certDER, nullptr, keepGoing);
      }
      if (rv != Success) {
        return rv;
      }
      if (!keepGoing) {
        break;
      }
    }
  }

  return Success;
}

Result
CertListContainsExpectedKeys(const ScopedCERTCertList& certList,
                             const char* hostname, Time time,
                             PinningMode pinningMode)
{
  return Success; // XXX Replace implementation
}

// TODO(bug 1036065): It seems like we only construct CERTCertLists for the
// purpose of constructing nsNSSCertLists, so maybe we should change this
// function to output an nsNSSCertList instead.
SECStatus
ConstructCERTCertListFromReversedDERArray(
  const mozilla::pkix::DERArray& certArray,
  /*out*/ ScopedCERTCertList& certList)
{
  certList = CERT_NewCertList();
  if (!certList) {
    return SECFailure;
  }

  CERTCertDBHandle* certDB(CERT_GetDefaultCertDB()); // non-owning

  size_t numCerts = certArray.GetLength();
  for (size_t i = 0; i < numCerts; ++i) {
    SECItem certDER(UnsafeMapInputToSECItem(*certArray.GetDER(i)));
    ScopedCERTCertificate cert(CERT_NewTempCertificate(certDB, &certDER,
                                                       nullptr, false, true));
    if (!cert) {
      return SECFailure;
    }

    // certArray is ordered with the root first, but we want the resulting
    // certList to have the root last.
    if (CERT_AddCertToListHead(certList.get(), cert.get()) != SECSuccess) {
      return SECFailure;
    }
    cert.release(); // cert is now owned by certList.
  }

  return SECSuccess;
}

Result
NSSCertDBTrustDomain::IsChainValid(const mozilla::pkix::DERArray& certArray,
                               mozilla::pkix::Time time)
{
  ScopedCERTCertList certList;
  SECStatus srv = ConstructCERTCertListFromReversedDERArray(certArray,
                                                            certList);
  if (srv != SECSuccess) {
    return MapPRErrorCodeToResult(PR_GetError());
  }

  Result result = CertListContainsExpectedKeys(certList, mHostname, time,
                                               mPinningMode);
  if (result != Success) {
    return result;
  }

  if (mBuiltChain) {
    *mBuiltChain = certList.release();
  }

  return Success;
}

Result
NSSCertDBTrustDomain::VerifyAndMaybeCacheEncodedOCSPResponse(
  const CertID& certID, Time time, uint16_t maxLifetimeInDays,
  Input encodedResponse, EncodedResponseSource responseSource,
  /*out*/ bool& expired)
{
  return Success; // XXX Implement
}

Result
NSSCertDBTrustDomain::CheckRevocation(
                      mozilla::pkix::EndEntityOrCA endEntityOrCA,
                      const mozilla::pkix::CertID& certID,
                      mozilla::pkix::Time time,
         /*optional*/ const mozilla::pkix::Input* stapledOCSPResponse,
         /*optional*/ const mozilla::pkix::Input* aiaExtension)
{
  // Actively distrusted certificates will have already been blocked by
  // GetCertTrust.

  // TODO: need to verify that IsRevoked isn't called for trust anchors AND
  // that that fact is documented in mozillapkix.

  PR_LOG(gCertVerifierLog, PR_LOG_DEBUG,
         ("NSSCertDBTrustDomain: Top of CheckRevocation\n"));

  // Bug 991815: The BR allow OCSP for intermediates to be up to one year old.
  // Since this affects EV there is no reason why DV should be more strict
  // so all intermediatates are allowed to have OCSP responses up to one year
  // old.
  uint16_t maxOCSPLifetimeInDays = 10;
  if (endEntityOrCA == EndEntityOrCA::MustBeCA) {
    maxOCSPLifetimeInDays = 365;
  }

  // If we have a stapled OCSP response then the verification of that response
  // determines the result unless the OCSP response is expired. We make an
  // exception for expired responses because some servers, nginx in particular,
  // are known to serve expired responses due to bugs.
  // We keep track of the result of verifying the stapled response but don't
  // immediately return failure if the response has expired.
  Result stapledOCSPResponseResult = Success;
  if (stapledOCSPResponse) {
    PR_ASSERT(endEntityOrCA == EndEntityOrCA::MustBeEndEntity);
    bool expired;
    stapledOCSPResponseResult =
      VerifyAndMaybeCacheEncodedOCSPResponse(certID, time,
                                             maxOCSPLifetimeInDays,
                                             *stapledOCSPResponse,
                                             ResponseWasStapled, expired);
    if (stapledOCSPResponseResult == Success) {
      // stapled OCSP response present and good
      // Telemetry::Accumulate(Telemetry::SSL_OCSP_STAPLING, 1);
      PR_LOG(gCertVerifierLog, PR_LOG_DEBUG,
             ("NSSCertDBTrustDomain: stapled OCSP response: good"));
      return Success;
    }
    if (stapledOCSPResponseResult == Result::ERROR_OCSP_OLD_RESPONSE ||
        expired) {
      // stapled OCSP response present but expired
      // Telemetry::Accumulate(Telemetry::SSL_OCSP_STAPLING, 3);
      PR_LOG(gCertVerifierLog, PR_LOG_DEBUG,
             ("NSSCertDBTrustDomain: expired stapled OCSP response"));
    } else {
      // stapled OCSP response present but invalid for some reason
      // Telemetry::Accumulate(Telemetry::SSL_OCSP_STAPLING, 4);
      PR_LOG(gCertVerifierLog, PR_LOG_DEBUG,
             ("NSSCertDBTrustDomain: stapled OCSP response: failure"));
      return stapledOCSPResponseResult;
    }
  } else {
    // no stapled OCSP response
    // Telemetry::Accumulate(Telemetry::SSL_OCSP_STAPLING, 2);
    PR_LOG(gCertVerifierLog, PR_LOG_DEBUG,
           ("NSSCertDBTrustDomain: no stapled OCSP response"));
  }


  // XXX TODO XXX
  return Success;//Result::FATAL_ERROR_LIBRARY_FAILURE;
}

Result
NSSCertDBTrustDomain::CheckPublicKey(mozilla::pkix::Input subjectPublicKeyInfo)
{
  return ::mozilla::pkix::CheckPublicKey(subjectPublicKeyInfo,
                                         mMinimumNonECCBits);
}

Result
NSSCertDBTrustDomain::VerifySignedData(
                      const mozilla::pkix::SignedDataWithSignature& signedData,
                      mozilla::pkix::Input subjectPublicKeyInfo)
{
  return ::mozilla::pkix::VerifySignedData(signedData, subjectPublicKeyInfo,
                                           mMinimumNonECCBits, mPinArg);
}

Result
NSSCertDBTrustDomain::DigestBuf(mozilla::pkix::Input item,
                            /*out*/ uint8_t* digestBuf,
                            size_t digestBufLen)
{
  return ::mozilla::pkix::DigestBuf(item, digestBuf, digestBufLen);
}

} } // namespace nss::mozpkix
