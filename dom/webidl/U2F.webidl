/* -*- Mode: IDL; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * The origin of this IDL file is
 * https://dvcs.w3.org/hg/webcrypto-api/raw-file/tip/spec/Overview.html#crypto-interface
 */

[NoInterfaceObject]
interface GlobalU2F {
  [Throws] readonly attribute U2F u2f;
};

typedef unsigned short ErrorCode;

dictionary ClientData {
    DOMString             typ;
    DOMString             challenge;
    DOMString             origin;
};

dictionary RegisterRequest {
    DOMString version;
    DOMString challenge;
    DOMString appId;
};

dictionary RegisterResponse {
    DOMString registrationData;
    DOMString clientData;

    // From Error
    ErrorCode? errorCode;
    DOMString? errorMessage;
};

dictionary SignRequest {
    DOMString version;
    DOMString challenge;
    DOMString keyHandle;
    DOMString appId;
};

dictionary SignResponse {
    DOMString keyHandle;
    DOMString signatureData;
    DOMString clientData;

    // From Error
    ErrorCode? errorCode;
    DOMString? errorMessage;
};

callback U2FRegisterCallback = void(RegisterResponse response);
callback U2FSignCallback = void(SignResponse response);

interface U2F {
  const unsigned short OK = 0;
  const unsigned short OTHER_ERROR = 1;
  const unsigned short BAD_REQUEST = 2;
  const unsigned short CONFIGURATION_UNSUPPORTED = 3;
  const unsigned short DEVICE_INELIGIBLE = 4;
  const unsigned short TIMEOUT = 5;

  [Throws]
  void register (sequence<RegisterRequest> registerRequests,
                 sequence<SignRequest> signRequests,
                 U2FRegisterCallback callback,
                 optional long? opt_timeoutSeconds);

  [Throws]
  void sign (sequence<SignRequest> signRequests,
             U2FSignCallback callback,
             optional long? opt_timeoutSeconds);
};
