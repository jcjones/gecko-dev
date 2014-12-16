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

#import "trust_domain.h"

void MOZ_PKIX_Initialize() {
  nss::pkix::NSSCertDBTrustDomain trustDomain;

}

SECStatus
MOZ_PKIX_VerifyCertChain() {
  nss::pkix::NSSCertDBTrustDomain trustDomain;
  return SECStatus::SECFailure;
}
