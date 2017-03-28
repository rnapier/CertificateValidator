//
//  CertificateValidator.swift
//  CertificateValidator
//
//  Created by Rob Napier on 3/28/17.
//  Copyright © 2017 Rob Napier. All rights reserved.
//

import Foundation
import Security

/**
 Pinned certificate validator.

 1. Put your trusted certificate in your bundle.
 2. Create a validator with -initWithCertificatePath:.
 3. In -connection:willSendRequestForAuthenticationChallenge:, call [validator validateChallenge:challenge]

 If you don't have your certificate in a handy file, pull it from your server:

 openssl s_client -connect myserver:443 </dev/null 2>/dev/null | openssl x509 -outform DER > myserver.cer

 */


class CertificateValidator: NSObject {
    enum Error: Swift.Error {
        case badCertificate
    }
    var trustedCertificates: [SecCertificate]

    init(trustedCertificates: [SecCertificate]) {
        self.trustedCertificates = trustedCertificates
    }

    convenience init(certificateURL: URL) throws {
        let data = try Data(contentsOf: certificateURL)
        guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
            throw Error.badCertificate
        }
        self.init(trustedCertificates: [certificate])
    }
}

extension CertificateValidator: URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let protectionSpace = challenge.protectionSpace

        if (protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust) {

            if let trust = protectionSpace.serverTrust {
                SecTrustSetAnchorCertificates(trust, trustedCertificates as CFArray)
                SecTrustSetAnchorCertificatesOnly(trust, true)

                var result = SecTrustResultType.invalid
                let status = SecTrustEvaluate(trust, &result)
                if status == errSecSuccess {
                    switch result {
                    case .proceed, .unspecified:
                        completionHandler(.useCredential, URLCredential(trust: trust))
                        return

                    default:
                        print("Could not verify certificate: \(result)")
                    }
                }
            }
        }

        // Something failed. Cancel
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
