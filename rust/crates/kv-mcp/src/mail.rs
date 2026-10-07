//! OAuth authentication for mail protocols: XOAUTH2 (used by IMAP/SMTP for both Gmail and
//! Outlook/Microsoft 365).
//! The IMAP test runs in the MCP process (as a regular user) and only ever uses a short-lived
//! access token. Direct port of src/server/mail.ts.

use base64::engine::{general_purpose::STANDARD, Engine};
use serde::Serialize;
use std::sync::LazyLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub static IMAP_HOSTS: LazyLock<std::collections::HashMap<&'static str, &'static str>> =
    LazyLock::new(|| {
        [
            ("outlook", "outlook.office365.com"),
            ("microsoft", "outlook.office365.com"),
            ("google", "imap.gmail.com"),
        ]
        .into()
    });

/// SASL XOAUTH2 initial response: base64("user=<u>^Aauth=Bearer <token>^A^A").
pub fn xoauth2(username: &str, access_token: &str) -> String {
    STANDARD.encode(format!(
        "user={username}\x01auth=Bearer {access_token}\x01\x01"
    ))
}

#[derive(Debug, Clone, Serialize)]
pub struct ImapTestResult {
    pub authenticated: bool,
    pub host: String,
    pub username: String,
    /// Inbox message count (read-only EXAMINE, doesn't change any message state).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbox_messages: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_error: Option<String>,
}

pub struct ImapTestOpts<'a> {
    pub host: &'a str,
    pub port: Option<u16>,
    pub username: &'a str,
    pub access_token: &'a str,
    pub timeout: std::time::Duration,
}

/// Logs into IMAP using XOAUTH2, opens the inbox read-only, then logs out.
/// On auth failure, the server first sends a "+ <base64 JSON>" error detail, which is decoded and
/// returned.
pub async fn imap_xoauth2_test(opts: ImapTestOpts<'_>) -> Result<ImapTestResult, String> {
    let host = opts.host.to_string();
    let username = opts.username.to_string();
    let fut = async {
        let port = opts.port.unwrap_or(993);
        let tcp = tokio::net::TcpStream::connect((opts.host, port))
            .await
            .map_err(|e| {
                kv_i18n::t(
                    &format!("连接 {host} 失败：{e}"),
                    &format!("Connection to {host} failed: {e}"),
                )
            })?;
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(opts.host.to_string())
            .map_err(|_| kv_i18n::t("host 格式不对", "Invalid host format"))?;
        let mut stream = connector.connect(server_name, tcp).await.map_err(|e| {
            kv_i18n::t(
                &format!("连接 {host} 失败：{e}"),
                &format!("Connection to {host} failed: {e}"),
            )
        })?;

        #[derive(PartialEq)]
        enum Stage {
            Greeting,
            Auth,
            Examine,
        }
        let mut stage = Stage::Greeting;
        let mut server_error: Option<String> = None;
        let mut inbox: Option<u64> = None;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let examine_re = regex::Regex::new(r"^\* (\d+) EXISTS").unwrap();

        loop {
            let n = stream.read(&mut chunk).await.map_err(|e| {
                kv_i18n::t(
                    &format!("连接 {host} 失败：{e}"),
                    &format!("Connection to {host} failed: {e}"),
                )
            })?;
            if n == 0 {
                return Err(kv_i18n::t(
                    &format!("连接 {host} 意外关闭"),
                    &format!("Connection to {host} closed unexpectedly"),
                ));
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 1_000_000 {
                return Err(kv_i18n::t("IMAP 响应过大", "IMAP response too large"));
            }
            while let Some(pos) = find_crlf(&buf) {
                let line = String::from_utf8_lossy(&buf[..pos]).to_string();
                buf.drain(..pos + 2);
                match stage {
                    Stage::Greeting => {
                        if !line.starts_with("* OK") {
                            return Ok(ImapTestResult {
                                authenticated: false,
                                host: host.clone(),
                                username: username.clone(),
                                inbox_messages: None,
                                server_error: Some(kv_i18n::t(
                                    &format!("意外的问候：{}", clip(&line, 200)),
                                    &format!("Unexpected greeting: {}", clip(&line, 200)),
                                )),
                            });
                        }
                        stage = Stage::Auth;
                        let cmd = format!(
                            "A1 AUTHENTICATE XOAUTH2 {}\r\n",
                            xoauth2(opts.username, opts.access_token)
                        );
                        stream
                            .write_all(cmd.as_bytes())
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    Stage::Auth => {
                        if let Some(detail) = line.strip_prefix('+') {
                            let detail = detail.trim();
                            server_error = Some(
                                STANDARD
                                    .decode(detail)
                                    .ok()
                                    .and_then(|b| String::from_utf8(b).ok())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or_else(|| detail.to_string()),
                            );
                            stream.write_all(b"\r\n").await.map_err(|e| e.to_string())?;
                        } else if line.starts_with("A1 OK") {
                            stage = Stage::Examine;
                            stream
                                .write_all(b"A2 EXAMINE INBOX\r\n")
                                .await
                                .map_err(|e| e.to_string())?;
                        } else if let Some(rest) = line.strip_prefix("A1 ") {
                            let joined: String = [Some(rest.to_string()), server_error.clone()]
                                .into_iter()
                                .flatten()
                                .collect::<Vec<_>>()
                                .join(" | ");
                            return Ok(ImapTestResult {
                                authenticated: false,
                                host: host.clone(),
                                username: username.clone(),
                                inbox_messages: None,
                                server_error: Some(clip(&joined, 500)),
                            });
                        }
                    }
                    Stage::Examine => {
                        if let Some(c) = examine_re.captures(&line) {
                            inbox = c[1].parse().ok();
                        }
                        if line.starts_with("A2 ") {
                            let _ = stream.write_all(b"A3 LOGOUT\r\n").await;
                            return Ok(ImapTestResult {
                                authenticated: true,
                                host: host.clone(),
                                username: username.clone(),
                                inbox_messages: inbox,
                                server_error: None,
                            });
                        }
                    }
                }
            }
        }
    };
    tokio::time::timeout(opts.timeout, fut).await.map_err(|_| {
        kv_i18n::t(
            &format!("连接 {} 超时", opts.host),
            &format!("Connection to {} timed out", opts.host),
        )
    })?
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphMailResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unread: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent: Option<Vec<RecentMessage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct RecentMessage {
    pub received: String,
    pub from: String,
    pub subject: String,
}

pub struct GraphMailOpts<'a> {
    pub access_token: &'a str,
    pub folder: Option<&'a str>,
    pub top: Option<u32>,
    pub base_url: Option<&'a str>,
}

/// Reads a mail folder read-only via Microsoft Graph: message counts + sender/subject of the most
/// recent messages (doesn't change any message state).
pub async fn graph_mail_test(opts: GraphMailOpts<'_>) -> Result<GraphMailResult, String> {
    let base = opts.base_url.unwrap_or("https://graph.microsoft.com/v1.0");
    let folder_raw = opts.folder.unwrap_or("inbox");
    let folder = url::form_urlencoded::byte_serialize(folder_raw.as_bytes()).collect::<String>();
    let top = opts.top.unwrap_or(5).clamp(1, 20);
    let host = url::Url::parse(base)
        .map(|u| u.host_str().unwrap_or_default().to_string())
        .unwrap_or_default();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;

    async fn get(
        client: &reqwest::Client,
        url: &str,
        token: &str,
        host: &str,
    ) -> Result<(u16, serde_json::Value), String> {
        let res = client
            .get(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/json")
            .header("Accept-Encoding", "identity")
            .send()
            .await
            .map_err(|e| {
                kv_i18n::t(
                    &format!("请求 {host} 失败：{e}"),
                    &format!("Request to {host} failed: {e}"),
                )
            })?;
        let status = res.status().as_u16();
        let bytes = res.bytes().await.map_err(|e| e.to_string())?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(kv_i18n::t(
                &format!("{host} 的响应过大"),
                &format!("Response from {host} is too large"),
            ));
        }
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
        Ok((status, body))
    }

    let to_fail = |status: u16, body: &serde_json::Value| -> GraphMailResult {
        let err = body.get("error").cloned().unwrap_or_default();
        let code = err
            .get("code")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| format!("HTTP {status}"));
        let message = err.get("message").and_then(|v| v.as_str());
        let full = match message {
            Some(m) => format!("{code}: {m}"),
            None => code,
        };
        GraphMailResult {
            ok: false,
            folder: None,
            total: None,
            unread: None,
            recent: None,
            http_status: Some(status),
            error: Some(clip(&full, 300)),
        }
    };

    let (status, f) = get(
        &client,
        &format!(
            "{base}/me/mailFolders/{folder}?$select=displayName,totalItemCount,unreadItemCount"
        ),
        opts.access_token,
        &host,
    )
    .await?;
    if status != 200 {
        return Ok(to_fail(status, &f));
    }
    let (status, m) = get(&client, &format!("{base}/me/mailFolders/{folder}/messages?$top={top}&$select=subject,receivedDateTime,from&$orderby=receivedDateTime%20desc"), opts.access_token, &host).await?;
    if status != 200 {
        return Ok(to_fail(status, &m));
    }
    let recent = m
        .get("value")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|x| RecentMessage {
                    received: x
                        .get("receivedDateTime")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    from: x
                        .get("from")
                        .and_then(|f| f.get("emailAddress"))
                        .and_then(|e| e.get("address"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    subject: clip(
                        x.get("subject")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default(),
                        120,
                    ),
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(GraphMailResult {
        ok: true,
        folder: Some(
            f.get("displayName")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| opts.folder.unwrap_or("inbox").to_string()),
        ),
        total: f.get("totalItemCount").and_then(|v| v.as_i64()),
        unread: f.get("unreadItemCount").and_then(|v| v.as_i64()),
        recent: Some(recent),
        http_status: None,
        error: None,
    })
}
