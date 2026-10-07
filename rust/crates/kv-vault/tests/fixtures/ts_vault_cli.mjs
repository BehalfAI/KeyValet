// Tiny CLI around the real compiled TS Vault class, used only by kv-vault's cross-implementation
// compatibility test (tests/ts_compat.rs). Not part of the product; a test fixture only.
//
// Usage:
//   node ts_vault_cli.mjs <dist/helper/vault.js path> set   <dir> <type> <name> <value>
//   node ts_vault_cli.mjs <dist/helper/vault.js path> get   <dir> <type> <name>
import { pathToFileURL } from "node:url";

const [vaultJsPath, action, dir, type, name, value] = process.argv.slice(2);
const { Vault } = await import(pathToFileURL(vaultJsPath).href);

const vault = new Vault(dir);
vault.init();

if (action === "set") {
  const r = vault.set({ type, name, value });
  console.log(JSON.stringify(r));
} else if (action === "get") {
  const r = vault.get(type, name);
  console.log(JSON.stringify(r));
} else {
  console.error(`unknown action: ${action}`);
  process.exit(1);
}
