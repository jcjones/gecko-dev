/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/*
 * moz_pkix.h
 *
 * Lifecycle Functions for the Mozilla PKIX library.
 *
 */

#ifndef mozilla_pkix_nss__moz_pkix_h
#define mozilla_pkix_nss__moz_pkix_h

#import "certt.h"
#import "prtime.h"
#import "seccomon.h"

#ifdef __cplusplus
extern "C" {
#endif


void
MOZ_PKIX_Initialize();

SECStatus
MOZ_PKIX_VerifyCertChain(CERTCertificate *cert,
                         PRBool checkSig,
                         SECCertUsage certUsage, PRTime t, void *wincx,
      /* out */          CERTVerifyLog *log,
      /* optional out */ PRBool *sigerror,
      /* optional out */ PRBool *revoked);

PRBool
MOZ_PKIX_GetUseMozPKIXForValidation();

#ifdef __cplusplus
}
#endif

#endif // mozilla_pkix_nss__moz_pkix_h
