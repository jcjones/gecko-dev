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

#import "seccomon.h"

#ifdef __cplusplus
extern "C" {
#endif


void MOZ_PKIX_Initialize();
SECStatus MOZ_PKIX_VerifyCertChain();

#ifdef __cplusplus
}
#endif

#endif // mozilla_pkix_nss__moz_pkix_h
