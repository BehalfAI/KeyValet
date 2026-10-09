import CryptoKit
import Foundation
import LocalAuthentication
import Security

// Private key representations crossing this boundary are encrypted and device-bound; the
// derived AES key goes to the root parent in memory. A fresh LAContext and the key's ACL
// enforce authentication for each subprocess, rather than a separate boolean check.
@_cdecl("kv_enclave_key")
public func enclaveKey(
    _ create: Int32,
    _ blob: UnsafePointer<UInt8>, _ blobLength: Int,
    _ peer: UnsafePointer<UInt8>, _ peerLength: Int,
    _ reason: UnsafePointer<CChar>, _ cancel: UnsafePointer<CChar>,
    _ outputBlob: UnsafeMutablePointer<UInt8>, _ outputBlobLength: UnsafeMutablePointer<Int>,
    _ outputPeer: UnsafeMutablePointer<UInt8>, _ outputKey: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return -25291 }
    let context = LAContext()
    context.localizedReason = String(cString: reason)
    context.localizedCancelTitle = String(cString: cancel)
    context.touchIDAuthenticationAllowableReuseDuration = 0
    defer { context.invalidate() }
    do {
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        let publicPeer: P256.KeyAgreement.PublicKey
        if create != 0 {
            var error: Unmanaged<CFError>?
            guard let acl = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .userPresence], &error
            ) else { return -50 }
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                accessControl: acl, authenticationContext: context)
            // The software private half is never serialized or retained beyond this expression.
            publicPeer = P256.KeyAgreement.PrivateKey().publicKey
        } else {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: Data(bytes: blob, count: blobLength),
                authenticationContext: context)
            publicPeer = try P256.KeyAgreement.PublicKey(
                x963Representation: Data(bytes: peer, count: peerLength))
        }
        let secret = try key.sharedSecretFromKeyAgreement(with: publicPeer)
        let derived = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(),
            sharedInfo: Data("keyvalet/master-key/v1".utf8), outputByteCount: 32)
        let representation = key.dataRepresentation
        guard representation.count <= outputBlobLength.pointee else { return -50 }
        representation.copyBytes(to: outputBlob, count: representation.count)
        outputBlobLength.pointee = representation.count
        publicPeer.x963Representation.copyBytes(to: outputPeer, count: 65)
        derived.withUnsafeBytes { bytes in
            outputKey.update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 32)
        }
        return 0
    } catch {
        // Never serialize CryptoKit errors or key representations to logs.
        let code = (error as NSError).code
        return code == 0 ? -1 : Int32(clamping: code)
    }
}
