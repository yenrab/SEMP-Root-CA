//
//  main.swift
//  SEMP Root CA
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

