//
//  gen_root.swift
//  SEMP Root CA
//
//Copyright (c) 2025 Lee Barney
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.
//
//  Created by Barney, Lee on 1/3/25.
//

import Foundation
import X509
import SwiftASN1
import Crypto

/// A helper to wrap raw DER bytes in a PEM "BEGIN/END" block.
func pemBlock(header: String, derBytes: [UInt8]) -> String {
    let base64 = Data(derBytes).base64EncodedString(options: [.lineLength64Characters])
    return """
    -----BEGIN \(header)-----
    \(base64)
    -----END \(header)-----
    """
}

/// Generate a self-signed CA certificate + private key (DER-encoded).
/// This is based on the code you previously shared.
func generateCACertificate() throws -> (certificateDER: [UInt8], privateKeyDER: [UInt8]) {
    // 1) Generate the Swift Crypto private key (P256 ECDSA)
    let swiftCryptoKey = P256.Signing.PrivateKey()
    // 2) Wrap it in swift-certificates PrivateKey
    let key = Certificate.PrivateKey(swiftCryptoKey)

    // 3) Build subject name (and issuer name, since it’s self-signed)
    let subjectName = try DistinguishedName {
        CommonName("SEMP Kademlia CA")
    }
    let issuerName = subjectName

    // 4) Time boundaries
    let now = Date()

    // 5) Build the X.509 extensions: CA = true, keyCertSign usage, etc.
    let extensions = try Certificate.Extensions {
        Critical(
            BasicConstraints.isCertificateAuthority(maxPathLength: nil)
        )
        Critical(
            KeyUsage(keyCertSign: true)
        )
        // Example SAN
        SubjectAlternativeNames([.dnsName("localhost")])
    }

    // 6) Create the self-signed certificate
    let certificate = try Certificate(
        version: .v3,
        serialNumber: Certificate.SerialNumber(),
        publicKey: key.publicKey,
        notValidBefore: now,
        notValidAfter: now.addingTimeInterval(60 * 60 * 24 * 365),
        issuer: issuerName,
        subject: subjectName,
        signatureAlgorithm: .ecdsaWithSHA256,
        extensions: extensions,
        issuerPrivateKey: key
    )

    // 7) Serialize the certificate to DER
    var serializer = DER.Serializer()
    try serializer.serialize(certificate)
    let derEncodedCertificate = serializer.serializedBytes

    // 8) Also grab the private key in DER
    let derEncodedPrivateKey = swiftCryptoKey.derRepresentation

    return (derEncodedCertificate, Array(derEncodedPrivateKey))
}
