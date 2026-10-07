//! Protocol-based credentials: OAuth2, generic JWT signing, GitHub App, Google service account,
//! AWS (STS), TOTP. Direct port of src/helper/protocols/*.

pub mod aws;
pub mod check;
pub mod github_app;
pub mod google_sa;
pub mod http;
pub mod index;
pub mod jwt;
pub mod jwt_kind;
pub mod oauth2;
pub mod totp;
