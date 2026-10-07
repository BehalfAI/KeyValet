import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { after, before, describe, it } from "node:test";
import http from "node:http";
import { graphMailTest, imapXoauth2Test, xoauth2 } from "../server/mail.js";

let server: tls.Server;
let port = 0;
let cert = "";
const received: string[] = [];

before(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "credmcp-imap-"));
  execFileSync("/usr/bin/openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost", "-keyout", path.join(dir, "k.pem"), "-out", path.join(dir, "c.pem"),
  ], { stdio: "ignore" });
  cert = fs.readFileSync(path.join(dir, "c.pem"), "utf8");
  server = tls.createServer({ key: fs.readFileSync(path.join(dir, "k.pem")), cert }, (sock) => {
    sock.setEncoding("utf8");
    sock.write("* OK IMAP4 ready\r\n");
    let failing = false;
    let buf = "";
    sock.on("data", (d: string) => {
      buf += d;
      let nl: number;
      while ((nl = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        received.push(line);
        if (line.startsWith("A1 AUTHENTICATE XOAUTH2 ")) {
          const sasl = Buffer.from(line.slice(24), "base64").toString();
          if (sasl === "user=me@example.com\x01auth=Bearer good-token\x01\x01") sock.write("A1 OK AUTHENTICATE completed.\r\n");
          else {
            failing = true;
            sock.write(`+ ${Buffer.from('{"status":"401","schemes":"bearer","scope":"https://outlook.office.com/"}').toString("base64")}\r\n`);
          }
        } else if (line === "" && failing) {
          sock.write("A1 NO AUTHENTICATE failed.\r\n");
        } else if (line === "A2 EXAMINE INBOX") {
          sock.write("* FLAGS (\\Seen)\r\n* 7 EXISTS\r\n* 0 RECENT\r\nA2 OK [READ-ONLY] EXAMINE completed.\r\n");
        } else if (line === "A3 LOGOUT") {
          sock.end("* BYE\r\nA3 OK LOGOUT completed.\r\n");
        }
      }
    });
    sock.on("error", () => {});
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as { port: number }).port;
});

after(() => server.close());

describe("XOAUTH2 / IMAP", () => {
  it("XOAUTH2 string format", () => {
    assert.equal(Buffer.from(xoauth2("a@b.c", "tok"), "base64").toString(), "user=a@b.c\x01auth=Bearer tok\x01\x01");
  });

  it("successful login: opens the inbox read-only and returns the message count", async () => {
    const r = await imapXoauth2Test({ host: "localhost", port, username: "me@example.com", accessToken: "good-token", ca: cert });
    assert.deepEqual(r, { authenticated: true, host: "localhost", username: "me@example.com", inbox_messages: 7 });
    assert.ok(received.includes("A2 EXAMINE INBOX"), "uses the read-only EXAMINE instead of SELECT");
  });

  it("failed login: decodes the error detail returned by the server", async () => {
    const r = await imapXoauth2Test({ host: "localhost", port, username: "me@example.com", accessToken: "bad-token", ca: cert });
    assert.equal(r.authenticated, false);
    assert.match(r.server_error!, /AUTHENTICATE failed/);
    assert.match(r.server_error!, /"status":"401"/);
  });
});

describe("Microsoft Graph mail", () => {
  let graph: http.Server;
  let base = "";
  const paths: string[] = [];
  before(async () => {
    graph = http.createServer((req, res) => {
      paths.push(decodeURIComponent(req.url!));
      res.setHeader("Content-Type", "application/json");
      if (req.headers.authorization !== "Bearer good") {
        res.writeHead(401).end(JSON.stringify({ error: { code: "InvalidAuthenticationToken", message: "token expired" } }));
        return;
      }
      const u = new URL(req.url!, "http://x");
      if (u.pathname === "/me/mailFolders/inbox") {
        res.end(JSON.stringify({ displayName: "Inbox", totalItemCount: 60, unreadItemCount: 41 }));
      } else if (u.pathname === "/me/mailFolders/inbox/messages") {
        res.end(JSON.stringify({ value: [{ subject: "Order #6", receivedDateTime: "2026-10-06T09:00:00Z", from: { emailAddress: { address: "shop@example.com" } } }] }));
      } else {
        res.writeHead(404).end("{}");
      }
    });
    await new Promise<void>((r) => graph.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(graph.address() as { port: number }).port}`;
  });
  after(() => graph.close());

  it("read-only view of the inbox: counts + recent messages", async () => {
    const r = await graphMailTest({ accessToken: "good", baseUrl: base, top: 3 });
    assert.deepEqual(r, {
      ok: true, folder: "Inbox", total: 60, unread: 41,
      recent: [{ received: "2026-10-06T09:00:00Z", from: "shop@example.com", subject: "Order #6" }],
    });
    assert.ok(paths.some((p) => p.includes("$top=3") && p.includes("$orderby=receivedDateTime desc")));
    assert.ok(paths.every((p) => !/\/(move|send|delete)/i.test(p)), "only read-only requests");
  });

  it("returns error details when the token is rejected", async () => {
    const r = await graphMailTest({ accessToken: "bad", baseUrl: base });
    assert.deepEqual(r, { ok: false, http_status: 401, error: "InvalidAuthenticationToken: token expired" });
  });
});
