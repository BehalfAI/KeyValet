use crate::crypto::{self, AAD, KEY_BYTES, LEGACY_AAD, NONCE_BYTES};
use crate::error::{Result, VaultError};
use crate::types::{CredentialRecord, HttpConfig, Kind, TypeRecord, VaultData, KINDS};
use crate::validate::{
    check_attributes, check_description, check_value, normalize_name, normalize_type,
    MAX_PROTOCOL_BYTES,
};
use aes_gcm::aead::{rand_core::RngCore, OsRng};
use serde::Serialize;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const LOCK_TIMEOUT: Duration = Duration::from_millis(10_000);
const LOCK_STALE: Duration = Duration::from_millis(30_000);

pub struct Vault {
    pub dir: PathBuf,
    key_path: PathBuf,
    data_path: PathBuf,
    audit_path: PathBuf,
    lock_path: PathBuf,
    key: std::sync::Mutex<Option<Zeroizing<[u8; KEY_BYTES]>>>,
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Mirrors `own()` in vault.ts: a named helper only so call sites read the same way; `HashMap::get`
/// already doesn't walk a prototype chain the way plain JS property access would.
fn own<'a, V>(map: &'a HashMap<String, V>, key: &str) -> Option<&'a V> {
    map.get(key)
}

impl Vault {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        Self {
            key_path: dir.join("master.key"),
            data_path: dir.join("vault.enc"),
            audit_path: dir.join("audit.log"),
            lock_path: dir.join(".lock"),
            dir,
            key: std::sync::Mutex::new(None),
        }
    }

    /// Creates/checks the directory and master key. Refuses to work when directory or file
    /// permissions are wrong, rather than "fixing" them.
    pub fn init(&self) -> Result<()> {
        if !self.dir.exists() {
            std::fs::create_dir(&self.dir)?;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        }
        self.assert_private(&self.dir, true)?;

        if !self.key_path.exists() {
            let mut key_bytes = [0u8; KEY_BYTES];
            OsRng.fill_bytes(&mut key_bytes);
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&self.key_path)
            {
                Ok(mut f) => f.write_all(&key_bytes)?,
                // Another session initialized concurrently: use the key it wrote.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.assert_private(&self.key_path, false)?;
        let raw = std::fs::read(&self.key_path)?;
        if raw.len() != KEY_BYTES {
            return Err(VaultError::new(
                "主密钥文件已损坏（长度不对）",
                "Master key file is corrupted (wrong length)",
            ));
        }
        let mut key = [0u8; KEY_BYTES];
        key.copy_from_slice(&raw);
        let mut guard = self.key.lock().unwrap();
        *guard = Some(Zeroizing::new(key));
        // Best-effort: ask the OS to never swap out the page(s) holding the master key, so it
        // can't end up on disk in a swap file if this machine's swap isn't encrypted. Failure
        // (e.g. a locked-memory rlimit) isn't fatal -- this is defense in depth on top of the
        // zeroize-on-drop handling, not the only thing standing between the key and disk.
        if let Some(k) = guard.as_ref() {
            unsafe {
                libc::mlock(k.as_ptr() as *const libc::c_void, KEY_BYTES);
            }
        }
        drop(guard);

        if self.data_path.exists() {
            self.assert_private(&self.data_path, false)?;
            self.read()?; // fail fast if the key and data don't match
        }
        Ok(())
    }

    fn assert_private(&self, p: &Path, is_dir: bool) -> Result<()> {
        let st = std::fs::symlink_metadata(p)?;
        if st.file_type().is_symlink() {
            return Err(VaultError::new(
                &format!("{} 不能是符号链接", p.display()),
                &format!("{} must not be a symbolic link", p.display()),
            ));
        }
        if is_dir != st.is_dir() {
            return Err(VaultError::new(
                &format!("{} 类型不对", p.display()),
                &format!("{} has the wrong file type", p.display()),
            ));
        }
        if st.uid() != unsafe { libc::getuid() } {
            return Err(VaultError::new(
                &format!("{} 的属主不是当前用户（应为 root）", p.display()),
                &format!(
                    "{} is not owned by the current user (should be root)",
                    p.display()
                ),
            ));
        }
        if st.mode() & 0o077 != 0 {
            return Err(VaultError::new(
                &format!("{} 权限过宽（{:o}），必须只有属主可访问", p.display(), st.mode() & 0o777),
                &format!("{} has overly broad permissions ({:o}); it must be accessible only by its owner", p.display(), st.mode() & 0o777),
            ));
        }
        Ok(())
    }

    fn require_key(&self) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
        self.key
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| VaultError::new("凭证库未初始化", "Vault is not initialized"))
    }

    fn read(&self) -> Result<VaultData> {
        if !self.data_path.exists() {
            return Ok(VaultData::empty());
        }
        let file: crate::types::EncryptedFile =
            serde_json::from_slice(&std::fs::read(&self.data_path)?)?;
        if file.v != 1 || file.alg != "aes-256-gcm" {
            return Err(VaultError::new(
                "不支持的凭证库格式",
                "Unsupported vault format",
            ));
        }
        let key = self.require_key()?; // checked before the decrypt attempts: an uninitialized vault is a real error, not "tampered"
        let decode_err = || {
            VaultError::new("凭证库解密失败：数据被篡改或主密钥不匹配", "Failed to decrypt vault: data has been tampered with or the master key does not match")
        };
        let nonce_v = base64_decode(&file.iv).map_err(|_| decode_err())?;
        let tag_v = base64_decode(&file.tag).map_err(|_| decode_err())?;
        let ct = base64_decode(&file.ct).map_err(|_| decode_err())?;
        let nonce: [u8; NONCE_BYTES] = nonce_v.try_into().map_err(|_| decode_err())?;
        let tag: [u8; crate::crypto::TAG_BYTES] = tag_v.try_into().map_err(|_| decode_err())?;

        let mut plain: Option<Zeroizing<Vec<u8>>> = None;
        for aad in [AAD, LEGACY_AAD] {
            if let Ok(p) = crypto::decrypt(&key, &nonce, aad, &ct, &tag) {
                plain = Some(Zeroizing::new(p));
                break;
            }
        }
        let plain = plain.ok_or_else(decode_err)?;
        let data: VaultData = serde_json::from_slice(&plain)?;
        if data.version != 1 {
            return Err(VaultError::new(
                "不支持的凭证库版本",
                "Unsupported vault version",
            ));
        }
        Ok(data)
    }

    fn write(&self, data: &VaultData) -> Result<()> {
        let key = self.require_key()?;
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let plain = Zeroizing::new(serde_json::to_vec(data)?);
        let (ct, tag) = crypto::split_tag(crypto::encrypt(&key, &nonce, AAD, &plain));
        let file = crate::types::EncryptedFile {
            v: 1,
            alg: "aes-256-gcm".to_string(),
            iv: base64_encode(nonce),
            tag: base64_encode(tag),
            ct: base64_encode(&ct),
        };
        let bytes = serde_json::to_vec(&file)?;

        // Atomic write: temp file + fsync + rename, so a crash never leaves a half-written file.
        let mut tmp_name = self.data_path.clone().into_os_string();
        tmp_name.push(format!(".tmp-{}-{}", std::process::id(), random_hex(4)));
        let tmp = PathBuf::from(tmp_name);
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.data_path)?;
        std::fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Read-modify-write, holding the cross-process write lock.
    fn mutate<T>(&self, f: impl FnOnce(&mut VaultData) -> Result<T>) -> Result<T> {
        let _guard = self.lock()?;
        let mut data = self.read()?;
        let result = f(&mut data)?;
        self.write(&data)?;
        Ok(result)
    }

    fn lock(&self) -> Result<LockGuard<'_>> {
        let deadline = Instant::now() + LOCK_TIMEOUT;
        loop {
            match std::fs::create_dir(&self.lock_path) {
                Ok(()) => return Ok(LockGuard { vault: self }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
            match std::fs::metadata(&self.lock_path).and_then(|m| m.modified()) {
                Ok(modified) => {
                    if modified.elapsed().unwrap_or_default() > LOCK_STALE {
                        let _ = std::fs::remove_dir(&self.lock_path); // the lock holder crashed
                        continue;
                    }
                }
                Err(_) => continue, // the lock was just released
            }
            if Instant::now() > deadline {
                return Err(VaultError::new(
                    "凭证库正忙（获取写锁超时）",
                    "Vault is busy (timed out acquiring write lock)",
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn unlock(&self) {
        let _ = std::fs::remove_dir(&self.lock_path);
    }

    /// Reads the tail (at most `max_bytes`) of the audit log, as complete lines.
    pub fn read_audit_tail(&self, max_bytes: u64) -> Vec<String> {
        use std::io::{Read, Seek, SeekFrom};
        let Ok(mut f) = std::fs::File::open(&self.audit_path) else {
            return Vec::new();
        };
        let Ok(size) = f.metadata().map(|m| m.len()) else {
            return Vec::new();
        };
        let len = size.min(max_bytes);
        if f.seek(SeekFrom::Start(size - len)).is_err() {
            return Vec::new();
        }
        let mut buf = Vec::with_capacity(len as usize);
        if f.read_to_end(&mut buf).is_err() {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(&buf);
        let mut lines: Vec<&str> = text.split('\n').collect();
        if len < size {
            lines.remove(0); // the first line may be incomplete
        }
        lines
            .into_iter()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    }

    pub fn audit(&self, mut entry: serde_json::Map<String, serde_json::Value>) -> Result<()> {
        entry.insert("ts".to_string(), serde_json::Value::String(now_iso()));
        entry.insert(
            "pid".to_string(),
            serde_json::Value::Number(std::process::id().into()),
        );
        let mut line = serde_json::to_string(&serde_json::Value::Object(entry))?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.audit_path)?;
        f.write_all(line.as_bytes())?;
        drop(f);
        // Rotate once past 10MB (keeping the previous one), so it never grows unbounded.
        if let Ok(meta) = std::fs::metadata(&self.audit_path) {
            if meta.len() > 10 * 1024 * 1024 {
                let rotated = self.audit_path.with_extension("log.1");
                let _ = std::fs::rename(&self.audit_path, rotated);
            }
        }
        Ok(())
    }

    // ---------- operations ----------

    pub fn list_types(&self) -> Vec<ListTypesEntry> {
        let data = self.read().unwrap_or_else(|_| VaultData::empty());
        let mut names: Vec<&String> = data.types.keys().collect();
        names.sort();
        names
            .into_iter()
            .map(|name| {
                let rec = &data.types[name];
                let count = data.credentials.get(name).map(|c| c.len()).unwrap_or(0);
                ListTypesEntry {
                    name: name.clone(),
                    description: rec.description.clone(),
                    count,
                    created_at: rec.created_at.clone(),
                }
            })
            .collect()
    }

    pub fn type_exists(&self, ty: &str) -> Result<bool> {
        let ty = normalize_type(ty)?;
        Ok(own(&self.read()?.types, &ty).is_some())
    }

    pub fn create_type(&self, name: &str, description: Option<&str>) -> Result<CreateTypeResult> {
        let name = normalize_type(name)?;
        let description = check_description(description)?;
        self.mutate(|data| {
            if own(&data.types, &name).is_some() {
                return Ok(CreateTypeResult {
                    name: name.clone(),
                    created: false,
                });
            }
            let now = now_iso();
            data.types.insert(
                name.clone(),
                TypeRecord {
                    description: description.clone(),
                    created_at: now.clone(),
                    updated_at: now,
                },
            );
            data.credentials.insert(name.clone(), HashMap::new());
            Ok(CreateTypeResult {
                name: name.clone(),
                created: true,
            })
        })
    }

    pub fn delete_type(&self, name: &str) -> Result<String> {
        let name = normalize_type(name)?;
        self.mutate(|data| {
            if own(&data.types, &name).is_none() {
                return Err(VaultError::new(&format!("凭证类型 \"{name}\" 不存在"), &format!("Credential type \"{name}\" not found")));
            }
            let count = data.credentials.get(&name).map(|c| c.len()).unwrap_or(0);
            if count > 0 {
                return Err(VaultError::new(
                    &format!("凭证类型 \"{name}\" 下还有 {count} 个凭证，请先删除它们"),
                    &format!("Credential type \"{name}\" still has {count} credential(s); delete them first"),
                ));
            }
            data.types.remove(&name);
            data.credentials.remove(&name);
            Ok(name.clone())
        })
    }

    pub fn list(&self, ty: Option<&str>) -> Result<Vec<ListEntry>> {
        let data = self.read()?;
        let mut types: Vec<String> = match ty {
            None | Some("") => {
                let mut t: Vec<String> = data.types.keys().cloned().collect();
                t.sort();
                t
            }
            Some(ty) => {
                let ty = normalize_type(ty)?;
                if own(&data.types, &ty).is_none() {
                    return Err(VaultError::new(
                        &format!("凭证类型 \"{ty}\" 不存在"),
                        &format!("Credential type \"{ty}\" not found"),
                    ));
                }
                vec![ty]
            }
        };
        types.sort();
        let mut out = Vec::new();
        for ty in types.drain(..) {
            let Some(creds) = data.credentials.get(&ty) else {
                continue;
            };
            let mut names: Vec<&String> = creds.keys().collect();
            names.sort();
            for name in names {
                let c = &creds[name];
                out.push(ListEntry {
                    r#type: ty.clone(),
                    name: name.clone(),
                    kind: c.kind_or_static(),
                    description: c.description.clone(),
                    attributes: c.attributes.clone(),
                    template: c.template.clone(),
                    http: c.http.clone(),
                    updated_at: c.updated_at.clone(),
                });
            }
        }
        Ok(out)
    }

    pub fn exists(&self, ty: &str, name: &str) -> Result<bool> {
        let ty = normalize_type(ty)?;
        let name = normalize_name(name)?;
        Ok(self
            .read()?
            .credentials
            .get(&ty)
            .map(|c| c.contains_key(&name))
            .unwrap_or(false))
    }

    /// Full record (including secrets), deep-cloned. For the root helper's internal protocol
    /// implementations and the root CLI only.
    pub fn get_record(&self, ty: &str, name: &str) -> Result<(String, String, CredentialRecord)> {
        let ty = normalize_type(ty)?;
        let name = normalize_name(name)?;
        let data = self.read()?;
        if own(&data.types, &ty).is_none() {
            return Err(VaultError::new(
                &format!("凭证类型 \"{ty}\" 不存在"),
                &format!("Credential type \"{ty}\" not found"),
            ));
        }
        let rec = data
            .credentials
            .get(&ty)
            .and_then(|c| c.get(&name))
            .ok_or_else(|| {
                VaultError::new(
                    &format!("凭证 \"{ty}/{name}\" 不存在"),
                    &format!("Credential \"{ty}/{name}\" not found"),
                )
            })?;
        Ok((ty, name, rec.clone()))
    }

    /// Reads a static credential's value. A protocol-based credential's secrets cannot be read this way.
    pub fn get(&self, ty: &str, name: &str) -> Result<GetResult> {
        let (ty, name, mut c) = self.get_record(ty, name)?;
        if c.kind.is_some() && c.kind != Some(Kind::Static) {
            let kind = c.kind_or_static().as_str();
            return Err(VaultError::new(
                &format!("\"{ty}/{name}\" 是 {kind} 协议凭证，其长期秘密不能直接读取"),
                &format!("\"{ty}/{name}\" is a {kind} protocol credential; its long-term secrets cannot be read directly"),
            ));
        }
        if c.http.as_ref().is_some_and(|h| h.proxy_only) {
            return Err(VaultError::new(
                &format!("\"{ty}/{name}\" 设置为只能代理调用，不能读出秘密；请用 credential_http_request"),
                &format!("\"{ty}/{name}\" is proxy-only; its secret cannot be read. Use credential_http_request instead"),
            ));
        }
        // `c` implements Drop (to scrub its secret fields when it goes out of scope), which means
        // a field can't be moved out of it directly -- std::mem::take moves the value out and
        // leaves an empty default behind instead, same effect as a move without actually cloning
        // the secret into a second allocation first.
        Ok(GetResult {
            r#type: ty,
            name,
            value: std::mem::take(&mut c.value),
            fields: std::mem::take(&mut c.secrets),
            description: std::mem::take(&mut c.description),
            attributes: std::mem::take(&mut c.attributes),
            updated_at: std::mem::take(&mut c.updated_at),
        })
    }

    /// Writes a credential: creates the type first if missing, then writes the value. Both steps
    /// happen under the same write lock and in the same flush, so there's no "type created but
    /// value not written" intermediate state.
    pub fn set(&self, params: SetParams) -> Result<SetResult> {
        let ty = normalize_type(&params.r#type)?;
        let name = normalize_name(&params.name)?;
        let secrets = params.secrets.filter(|s| !s.is_empty());
        let value = if secrets.is_some() && params.value.as_deref().unwrap_or("").is_empty() {
            String::new()
        } else {
            check_value(params.value.as_deref())?
        };
        if let Some(s) = &secrets {
            if serde_json::to_vec(s)?.len() > MAX_PROTOCOL_BYTES {
                return Err(VaultError::new(
                    "秘密字段过大",
                    "Secret fields are too large",
                ));
            }
        }
        let description = check_description(params.description.as_deref())?;
        let attributes = check_attributes(params.attributes.as_ref())?;
        let type_description = check_description(params.type_description.as_deref())?;
        let overwrite = params.overwrite;

        self.mutate(|data| {
            let now = now_iso();
            let mut type_created = false;
            if own(&data.types, &ty).is_none() {
                data.types.insert(ty.clone(), TypeRecord { description: type_description.clone(), created_at: now.clone(), updated_at: now.clone() });
                type_created = true;
            }
            let creds = data.credentials.entry(ty.clone()).or_default();
            let existing = creds.get(&name).cloned();
            if existing.is_some() && !overwrite {
                return Err(VaultError::new(
                    &format!("凭证 \"{ty}/{name}\" 已存在；如需替换请设置 overwrite=true"),
                    &format!("Credential \"{ty}/{name}\" already exists; set overwrite=true to replace it"),
                ));
            }
            creds.insert(
                name.clone(),
                CredentialRecord {
                    kind: None,
                    value,
                    secrets,
                    http: params.http.clone(),
                    template: params.template.clone(),
                    description: if !description.is_empty() { description } else { existing.as_ref().map(|e| e.description.clone()).unwrap_or_default() },
                    attributes: if !attributes.is_empty() { attributes } else { existing.as_ref().map(|e| e.attributes.clone()).unwrap_or_default() },
                    created_at: existing.as_ref().map(|e| e.created_at.clone()).unwrap_or_else(|| now.clone()),
                    updated_at: now.clone(),
                    config: None,
                    state: None,
                    generation: None,
                },
            );
            data.types.get_mut(&ty).unwrap().updated_at = now;
            Ok(SetResult { r#type: ty.clone(), name: name.clone(), type_created, replaced: existing.is_some() })
        })
    }

    /// Writes a protocol-based credential. Same shape as `set`: creates the type first if missing.
    /// `config`/`secrets` are validated by the caller (the protocols crate).
    pub fn set_protocol(&self, params: SetProtocolParams) -> Result<SetResult> {
        let ty = normalize_type(&params.r#type)?;
        let name = normalize_name(&params.name)?;
        let description = check_description(params.description.as_deref())?;
        let type_description = check_description(params.type_description.as_deref())?;
        if params.kind == Kind::Static || !KINDS.contains(&params.kind) {
            return Err(VaultError::new(
                &format!("非法的协议种类 {:?}", params.kind),
                &format!("Invalid protocol kind {:?}", params.kind),
            ));
        }
        if serde_json::to_vec(&(&params.config, &params.secrets))?.len() > MAX_PROTOCOL_BYTES {
            return Err(VaultError::new(
                "协议凭证数据过大",
                "Protocol credential data is too large",
            ));
        }
        self.mutate(|data| {
            let now = now_iso();
            let mut type_created = false;
            if own(&data.types, &ty).is_none() {
                data.types.insert(ty.clone(), TypeRecord { description: type_description.clone(), created_at: now.clone(), updated_at: now.clone() });
                type_created = true;
            }
            let creds = data.credentials.entry(ty.clone()).or_default();
            let existing = creds.get(&name).cloned();
            if existing.is_some() && !params.overwrite {
                return Err(VaultError::new(
                    &format!("凭证 \"{ty}/{name}\" 已存在；如需替换请设置 overwrite=true"),
                    &format!("Credential \"{ty}/{name}\" already exists; set overwrite=true to replace it"),
                ));
            }
            creds.insert(
                name.clone(),
                CredentialRecord {
                    kind: Some(params.kind),
                    value: String::new(),
                    config: Some(params.config.clone()),
                    secrets: Some(params.secrets.clone()),
                    state: Some(serde_json::Value::Object(Default::default())),
                    generation: Some(random_hex(12)),
                    description: if !description.is_empty() { description } else { existing.as_ref().map(|e| e.description.clone()).unwrap_or_default() },
                    attributes: HashMap::new(),
                    created_at: existing.as_ref().map(|e| e.created_at.clone()).unwrap_or_else(|| now.clone()),
                    updated_at: now.clone(),
                    http: None,
                    template: None,
                },
            );
            data.types.get_mut(&ty).unwrap().updated_at = now;
            Ok(SetResult { r#type: ty.clone(), name: name.clone(), type_created, replaced: existing.is_some() })
        })
    }

    /// Modifies a protocol credential's state/secrets (e.g. a refreshed token) under the write lock.
    /// `generation` must match what was read: the credential being replaced during the operation
    /// (even to the same kind) is rejected, so a refreshed refresh-token can't be written back into
    /// a config the agent just swapped in behind our back.
    pub fn patch_record(
        &self,
        ty: &str,
        name: &str,
        kind: Kind,
        generation: Option<&str>,
        f: impl FnOnce(&mut CredentialRecord),
    ) -> Result<()> {
        let ty = normalize_type(ty)?;
        let name = normalize_name(name)?;
        self.mutate(|data| {
            let creds = data.credentials.get_mut(&ty);
            let rec = creds.and_then(|c| c.get_mut(&name));
            let Some(rec) = rec else {
                return Err(VaultError::new(&format!("凭证 \"{ty}/{name}\" 不存在"), &format!("Credential \"{ty}/{name}\" not found")));
            };
            if rec.kind_or_static() != kind || rec.generation.as_deref() != generation {
                return Err(VaultError::new(
                    &format!("凭证 \"{ty}/{name}\" 在操作期间被修改，已放弃写入，请重试"),
                    &format!("Credential \"{ty}/{name}\" was modified during the operation; write aborted, please retry"),
                ));
            }
            f(rec);
            rec.updated_at = now_iso();
            Ok(())
        })
    }

    /// Modifies the proxy configuration of any kind of credential. `f` returns the new
    /// configuration; validation is the caller's responsibility.
    pub fn update_http(
        &self,
        ty: &str,
        name: &str,
        f: impl FnOnce(CredentialRecord) -> Option<HttpConfig>,
    ) -> Result<()> {
        let ty = normalize_type(ty)?;
        let name = normalize_name(name)?;
        self.mutate(|data| {
            let rec = data
                .credentials
                .get(&ty)
                .and_then(|c| c.get(&name))
                .cloned();
            let Some(rec) = rec else {
                return Err(VaultError::new(
                    &format!("凭证 \"{ty}/{name}\" 不存在"),
                    &format!("Credential \"{ty}/{name}\" not found"),
                ));
            };
            let next = f(rec);
            let slot = data
                .credentials
                .get_mut(&ty)
                .unwrap()
                .get_mut(&name)
                .unwrap();
            slot.http = next;
            slot.updated_at = now_iso();
            Ok(())
        })
    }

    pub fn delete(&self, ty: &str, name: &str) -> Result<(String, String)> {
        let ty = normalize_type(ty)?;
        let name = normalize_name(name)?;
        self.mutate(|data| {
            let removed = data
                .credentials
                .get_mut(&ty)
                .map(|c| c.remove(&name))
                .unwrap_or(None);
            if removed.is_none() {
                return Err(VaultError::new(
                    &format!("凭证 \"{ty}/{name}\" 不存在"),
                    &format!("Credential \"{ty}/{name}\" not found"),
                ));
            }
            Ok((ty.clone(), name.clone()))
        })
    }
}

struct LockGuard<'a> {
    vault: &'a Vault,
}

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        self.vault.unlock();
    }
}

fn base64_encode(b: impl AsRef<[u8]>) -> String {
    use base64::engine::{general_purpose::STANDARD, Engine};
    STANDARD.encode(b)
}

fn base64_decode(s: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::engine::{general_purpose::STANDARD, Engine};
    STANDARD.decode(s)
}

#[derive(Debug, Clone, Serialize)]
pub struct ListTypesEntry {
    pub name: String,
    pub description: String,
    pub count: usize,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateTypeResult {
    pub name: String,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListEntry {
    pub r#type: String,
    pub name: String,
    pub kind: Kind,
    pub description: String,
    pub attributes: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpConfig>,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GetResult {
    pub r#type: String,
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<HashMap<String, String>>,
    pub description: String,
    pub attributes: HashMap<String, String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetResult {
    pub r#type: String,
    pub name: String,
    #[serde(rename = "typeCreated")]
    pub type_created: bool,
    pub replaced: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SetParams {
    pub r#type: String,
    pub name: String,
    pub value: Option<String>,
    pub secrets: Option<HashMap<String, String>>,
    pub http: Option<HttpConfig>,
    pub template: Option<String>,
    pub description: Option<String>,
    pub attributes: Option<HashMap<String, String>>,
    pub type_description: Option<String>,
    pub overwrite: bool,
}

#[derive(Debug, Clone)]
pub struct SetProtocolParams {
    pub r#type: String,
    pub name: String,
    pub kind: Kind,
    pub config: serde_json::Value,
    pub secrets: HashMap<String, String>,
    pub description: Option<String>,
    pub type_description: Option<String>,
    pub overwrite: bool,
}
