//
//  CertificateValidator.swift
//  CertificateValidator
//
//    MIT License
//
//    Copyright (c) 2017 Rob Napier
//
//    Permission is hereby granted, free of charge, to any person obtaining a copy
//    of this software and associated documentation files (the "Software"), to deal
//    in the Software without restriction, including without limitation the rights
//    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the Software is
//    furnished to do so, subject to the following conditions:
//
//    The above copyright notice and this permission notice shall be included in all
//    copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//    SOFTWARE.

import Foundation
import Security

/**
 `CertificateValidator` validates a "pinned" certificate. This allows your code to trust only your own
 certificates, rather than [all the certificates trusted by the OS](https://support.apple.com/en-us/HT204132).

 Generally you will include a copy of your server certificate in your app bundle. If you don't have your
 certificate in a handy file, pull it from your server:

     openssl s_client -connect myserver:443 </dev/null 2>/dev/null | openssl x509 -outform DER > myserver.cer

 You can also use a certificate that has signed your server's certificate (if you maintain your own signing
 root).
 
 Once you've installed the certificate, you can most easily pin your certificate by making `CertificateValidator`
 the delegate of NSURLSession. For example:
 
     guard let url = Bundle.main.url(forResource: name, withExtension: "cer") else {
         preconditionFailure("\(name) not found")
     }

     try! validator = CertificateValidator(certificateURL: url)
     session = URLSession(configuration: .default, delegate: validator, delegateQueue: nil)

*/
public class CertificateValidator: NSObject {
    public enum Error: Swift.Error {
        case badCertificate
    }

    public var trustedCertificates: [SecCertificate]

    public init(trustedCertificates: [SecCertificate]) {
        self.trustedCertificates = trustedCertificates
    }

    public convenience init(certificateURL: URL) throws {
        let data = try Data(contentsOf: certificateURL)
        guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
            throw Error.badCertificate
        }
        self.init(trustedCertificates: [certificate])
    }

    public func credentialIfTrustedCertificate(for challenge: URLAuthenticationChallenge) -> URLCredential? {
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
                        return URLCredential(trust: trust)

                    default:
                        print("Could not verify certificate: \(result)")
                    }
                }
            }
        }

        // Something failed. Cancel
        return nil
    }

    public func evaluate(challenge: URLAuthenticationChallenge,
                         completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if let cred = credentialIfTrustedCertificate(for: challenge) {
            completionHandler(.useCredential, cred)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

extension CertificateValidator: URLSessionDelegate {
    public func urlSession(_ session: URLSession,
                           didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        evaluate(challenge: challenge, completionHandler: completionHandler)
    }
}
