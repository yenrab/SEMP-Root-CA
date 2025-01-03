//
//  main.swift
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

do {
    // 1) Generate the self-signed CA cert + private key
    let (certDER, keyDER) = try generateCACertificate()

    // 2) Convert to PEM format
    let certPEM = pemBlock(header: "CERTIFICATE", derBytes: certDER)
    let keyPEM  = pemBlock(header: "PRIVATE KEY", derBytes: keyDER)

    // 3) Write them to the current working directory
    let fm = FileManager.default
    let cwd = fm.currentDirectoryPath

    let crtPath = "\(cwd)/root.crt"
    let keyPath = "\(cwd)/root.key"

    try certPEM.write(toFile: crtPath, atomically: true, encoding: .utf8)
    try keyPEM.write(toFile: keyPath,  atomically: true, encoding: .utf8)

    print("Successfully wrote:")
    print("  - \(crtPath)")
    print("  - \(keyPath)")
}
catch {
    print("Error: \(error)")
}

