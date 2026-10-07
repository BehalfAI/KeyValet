use crate::session::HelperSession;
use rmcp::handler::server::router::tool::ToolRouter;
use std::sync::Arc;

#[derive(Clone)]
pub struct Server {
    pub session: Arc<HelperSession>,
    pub tool_router: ToolRouter<Server>,
}

impl Server {
    pub fn new(session: Arc<HelperSession>) -> Self {
        Self {
            session,
            tool_router: Self::basic_tool_router()
                + Self::http_tool_router()
                + Self::mail_tool_router()
                + Self::protocols_tool_router(),
        }
    }
}
