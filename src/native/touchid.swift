// Touch ID / 设备所有者认证（LocalAuthentication）。
// 由 root helper 降权为当前用户后调用（root 身份下指纹无法送达认证框）。
// 用法：touchid <原因文字> [取消按钮文字]；退出码：0 通过，1 未通过/取消，2 本机不支持。
// 没有指纹时系统认证框会改为要求输入登录密码——密码由系统校验，本程序拿不到。
import Foundation
import LocalAuthentication

let reason = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "解锁凭证库"
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
