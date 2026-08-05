//! ACP (Agent Client Protocol) server: speaks ACP on stdio, drives the
//! Reborn runtime for each prompt.
//!
//! Usage: `ironclaw acp-serve [--auto-approve] [--cwd <dir>]`
//!
//! ## Architecture
//!
//! Unlike the HTTP `serve` command (WebChat), this command:
//! - Uses `current_thread` tokio runtime (ACP stdio is !Send)
//! - Implements the `agent_client_protocol::Agent` trait
//! - Bridges each ACP `prompt()` call to `RebornRuntime::send_user_message()`
//! - Returns the assistant reply text in the `PromptResponse`

use std::sync::Arc;

use agent_client_protocol::{
    Agent, AgentSideConnection, AgentCapabilities, AuthenticateRequest, AuthenticateResponse,
    ContentBlock, Error, Implementation, InitializeRequest, InitializeResponse,
    NewSessionRequest, NewSessionResponse, PromptRequest, PromptResponse, ProtocolVersion,
    SessionId, StopReason,
};
use clap::Args;
use ironclaw_reborn_composition::{RebornRuntime, build_reborn_runtime};
use tokio::sync::Notify;
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::context::RebornCliContext;
use crate::runtime::{
    RuntimeInputCaller, RuntimeInputOptions, build_runtime_input_with_options,
};

// ── CLI Args ───────────────────────────────────────────────────────────────

#[derive(Debug, Args)]
pub(crate) struct AcpServeCommand {
    /// Auto-approve tool execution (skip confirmation gates).
    #[arg(long)]
    auto_approve: bool,

    /// Working directory for the agent.
    #[arg(long)]
    cwd: Option<String>,
}

// ── ACP Agent trait implementation ─────────────────────────────────────────

struct RebornAcpAgent {
    runtime: Arc<RebornRuntime>,
    cancel_notify: Arc<Notify>,
}

#[async_trait::async_trait(?Send)]
impl Agent for RebornAcpAgent {
    async fn initialize(
        &self,
        _args: InitializeRequest,
    ) -> std::result::Result<InitializeResponse, Error> {
        Ok(
            InitializeResponse::new(ProtocolVersion::from(2u16))
                .agent_capabilities(AgentCapabilities::new())
                .agent_info(Implementation::new("ironclaw", env!("CARGO_PKG_VERSION"))),
        )
    }

    async fn authenticate(
        &self,
        _args: AuthenticateRequest,
    ) -> std::result::Result<AuthenticateResponse, Error> {
        Ok(AuthenticateResponse::new())
    }

    async fn new_session(
        &self,
        _args: NewSessionRequest,
    ) -> std::result::Result<NewSessionResponse, Error> {
        let sid = uuid::Uuid::new_v4().to_string();
        Ok(NewSessionResponse::new(SessionId::new(sid)))
    }

    async fn prompt(
        &self,
        args: PromptRequest,
    ) -> std::result::Result<PromptResponse, Error> {
        let content: String = args
            .prompt
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.text.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");

        if content.is_empty() {
            return Err(Error::invalid_params());
        }

        // Create a new conversation for each ACP session prompt.
        // ACP sessions are stateless from our side — each prompt is a
        // standalone interaction matching the REPL pattern.
        let conversation = self
            .runtime
            .new_conversation()
            .await
            .map_err(|e| Error::new(-32603, format!("Failed to create conversation: {e}")))?;

        let reply = self
            .runtime
            .send_user_message(&conversation, &content)
            .await
            .map_err(|e| Error::new(-32603, format!("Agent run failed: {e}")))?;

        // TODO: support streaming mid-turn chunks via trajectory observer
        // and session notifications.

        let stop_reason = if reply.is_successful_final_reply() {
            StopReason::EndTurn
        } else {
            // ACP 0.10 has no Error stop reason — use MaxTurnRequests as
            // the closest "did not complete normally" signal.
            StopReason::MaxTurnRequests
        };

        Ok(PromptResponse::new(stop_reason))
    }

    async fn cancel(
        &self,
        _args: agent_client_protocol::CancelNotification,
    ) -> std::result::Result<(), Error> {
        self.cancel_notify.notify_waiters();
        Ok(())
    }
}

// ── Main entry point ──────────────────────────────────────────────────────

impl AcpServeCommand {
    pub(crate) fn execute(self, context: RebornCliContext) -> anyhow::Result<()> {
        if let Some(ref cwd) = self.cwd {
            std::env::set_current_dir(cwd)?;
        }

        if self.auto_approve {
            unsafe { std::env::set_var("IRONCLAW_REBORN_AUTO_APPROVE_TOOLS", "true") };
        }

        crate::runtime::init_tracing();
        let boot_config = context.boot_config().clone();

        // ACP stdio requires current_thread runtime because the Agent trait
        // is !Send (uses LocalSet for spawn_local).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        rt.block_on(async move {
            let built = build_runtime_input_with_options(
                &boot_config,
                RuntimeInputCaller::AcpServe,
                RuntimeInputOptions::default(),
            )?;

            let runtime = build_reborn_runtime(built.inner).await?;
            let runtime = Arc::new(runtime);

            let cancel_notify = Arc::new(Notify::new());
            let agent = RebornAcpAgent {
                runtime,
                cancel_notify,
            };

            let local_set = tokio::task::LocalSet::new();
            local_set
                .run_until(async {
                    let stdin = tokio::io::stdin();
                    let stdout = tokio::io::stdout();
                    let (_conn, io_task) = AgentSideConnection::new(
                        agent,
                        tokio_util::compat::TokioAsyncWriteCompatExt::compat_write(stdout),
                        TokioAsyncReadCompatExt::compat(stdin),
                        |fut| {
                            tokio::task::spawn_local(fut);
                        },
                    );

                    io_task
                        .await
                        .map_err(|e| anyhow::anyhow!("ACP I/O error: {e}"))?;
                    Ok::<(), anyhow::Error>(())
                })
                .await?;

            Ok::<(), anyhow::Error>(())
        })?;

        Ok(())
    }
}
