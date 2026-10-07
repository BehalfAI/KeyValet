// Touch ID / device owner authentication (LocalAuthentication).
// Invoked by the root helper after dropping privileges to the current user (fingerprints can't reach the auth sheet as root).
// Usage: touchid <reason text> [cancel button text]; exit codes: 0 approved, 1 not approved/cancelled, 2 unsupported on this machine.
// Without a fingerprint enrolled, the system auth sheet falls back to the login password — the system verifies it, this program never sees it.
import Foundation
import LocalAuthentication

let reason = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "Unlock the vault"
let ctx = LAContext()
ctx.localizedCancelTitle = CommandLine.arguments.count > 2 ? CommandLine.arguments[2] : "Cancel"
var err: NSError?
guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else { exit(2) }

let done = DispatchSemaphore(value: 0)
var ok = false
ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
  ok = success
  done.signal()
}
done.wait()
exit(ok ? 0 : 1)
