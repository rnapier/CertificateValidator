//
//  ViewController.swift
//  CertificateValidator
//
//  Created by Rob Napier on 3/28/17.
//  Copyright © 2017 Rob Napier. All rights reserved.
//

import UIKit
// To try this out, tap "Trust example.com" to only trust our www.example.com certificate. Tap "Trust google" to only
// trust Google's cert (it's only good until Jun 8, 2017, so after that you'll need to regenerate:
// openssl s_client -connect www.google.com:443 </dev/null 2>/dev/null | openssl x509 -outform DER > www.google.com.cer


let fetchURL = URL(string: "https://www.google.com")!

class ViewController: UIViewController {

    @IBOutlet weak var webView: UIWebView!

    var validator = CertificateValidator(trustedCertificates: [])
    var session = URLSession()
    var task: URLSessionDataTask?

    func run(withCertificateName name: String) {
        guard let url = Bundle.main.url(forResource: name, withExtension: "cer") else {
            preconditionFailure("\(name) not found")
        }

        try! validator = CertificateValidator(certificateURL: url)

        session = URLSession(configuration: .default, delegate: validator, delegateQueue: nil)

        task = session.dataTask(with: URLRequest(url: fetchURL)) { data, response, error in
            if let error = error {
                self.webView.loadHTMLString(error.localizedDescription, baseURL: nil)
            } else if let data = data {
                self.webView.load(data, mimeType: "text/html", textEncodingName: "utf-8", baseURL: fetchURL)
            }
        }
        task?.resume()
    }


    @IBAction func trustExample(_ sender: Any) {
        run(withCertificateName: "www.example.com")
    }

    @IBAction func trustGoogle(_ sender: Any) {
        run(withCertificateName: "www.google.com")
    }
}

