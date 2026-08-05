//! ACP (Agent Client Protocol) server: speaks ACP on stdio, drives the
//! Reborn runtime for each prompt.
//!
//! Usage: `ironclaw acp-serve [--auto-approve] [--cwd <dir>]`
//!
//! ## Architecture
//!
//! Unlike the HTTP `serve` command (WebChat), this command:
//! - Implements the `agent_client_protocol::Agent` trait on stdio
//! - Bridges each ACP `prompt()` call to `RebornRuntime::send_user_message()`
//! - Returns the assistant reply text in the `PromptResponse`
//!
//! The runtime boots identically to the `run` command (multi_thread tokio).
//! ACP I/O runs on a `LocalSet` inside the multi_thread runtime so the
//! !Send `Agent` trait impl works.

use std::sync::Arc;

use std::pin::Pin;

use agent_client_protocol::{
    Agent, AgentSideConnection, AgentCapabilities, AuthenticateRequest, AuthenticateResponse,
    Client, ContentBlock, ContentChunk, Error, Implementation, InitializeRequest,
    InitializeResponse, NewSessionRequest, NewSessionResponse, PromptRequest, PromptResponse,
    ProtocolVersion, SessionId, SessionNotification, SessionUpdate, StopReason,
};
use clap::Args;
use ironclaw_reborn_composition::{RebornRuntime, build_reborn_runtime};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;

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
    conn: Arc<std::sync::Mutex<Option<AgentSideConnection>>>,
    cancel_token: CancellationToken,
}

impl Clone for RebornAcpAgent {
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
            conn: self.conn.clone(),
            cancel_token: self.cancel_token.clone(),
        }
    }
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

        // Each ACP prompt creates a fresh conversation — ACP sessions are
        // stateless from our side.
        let conversation = self
            .runtime
            .new_conversation()
            .await
            .map_err(|e| Error::new(-32603, format!("Failed to create conversation: {e}")))?;

        let reply = self
            .runtime
            .send_user_message_with_cancellation(&conversation, &content, self.cancel_token.clone())
            .await
            .map_err(|e| Error::new(-32603, format!("Agent run failed: {e}")))?;

        let stop_reason = if reply.is_successful_final_reply() {
            StopReason::EndTurn
        } else {
            StopReason::MaxTurnRequests
        };

        // Stream the assistant reply text back as an AgentMessageChunk
        // notification so the client receives the content.
        if let Some(text) = &reply.text {
            if let Some(conn) = self.conn.lock().unwrap().as_ref() {
                let _ = conn.session_notification(
                    SessionNotification::new(
                        args.session_id,
                        SessionUpdate::AgentMessageChunk(
                            ContentChunk::new(ContentBlock::from(text.as_str())),
                        ),
                    ),
                ).await;
            }
        }

        Ok(PromptResponse::new(stop_reason))
    }

    async fn cancel(
        &self,
        _args: agent_client_protocol::CancelNotification,
    ) -> std::result::Result<(), Error> {
        self.cancel_token.cancel();
        Ok(())
    }
}

// ── Main entry point ──────────────────────────────────────────────────────

/// Wrapper that flushes stdout after every `write` call.
/// The ACP library writes JSON-RPC lines but never calls `flush()`, so
/// piped stdout would never deliver the response.
struct FlushingWrite<W> {
    inner: W,
}

impl<W> FlushingWrite<W> {
    fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<W: futures_io::AsyncWrite> futures_io::AsyncWrite for FlushingWrite<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // SAFETY: FlushingWrite is a repr-transparent wrapper over `inner`.
        // We never move `inner` and the struct has no Drop, so projecting
        // the pin is sound (pin-project pattern).
        let me = unsafe { self.get_unchecked_mut() };
        let result = unsafe { Pin::new_unchecked(&mut me.inner) }.poll_write(cx, buf);
        if result.is_ready() {
            let _ = unsafe { Pin::new_unchecked(&mut me.inner) }.poll_flush(cx);
        }
        result
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = unsafe { self.get_unchecked_mut() };
        unsafe { Pin::new_unchecked(&mut me.inner) }.poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = unsafe { self.get_unchecked_mut() };
        unsafe { Pin::new_unchecked(&mut me.inner) }.poll_close(cx)
    }
}

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

        // Sync setup — same as `run` command.
        let runtime_input =
            build_runtime_input_with_options(&boot_config, RuntimeInputCaller::AcpServe, RuntimeInputOptions::default())?
                .inner;

        // Multi-thread runtime — `build_reborn_runtime` spawns internal tasks
        // that deadlock on single-thread (confirmed by testing).
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        rt.block_on(async move {
            eprintln!("[ACP] building reborn runtime...");
            let runtime = build_reborn_runtime(runtime_input).await?;
            eprintln!("[ACP] reborn runtime built, starting ACP I/O");
            let runtime = Arc::new(runtime);
            let conn_slot: Arc<std::sync::Mutex<Option<AgentSideConnection>>> =
                Arc::new(std::sync::Mutex::new(None));
            let agent = RebornAcpAgent {
                runtime: runtime.clone(),
                conn: conn_slot.clone(),
                cancel_token: CancellationToken::new(),
            };

            // ACP I/O must run inside a LocalSet because the Agent trait is
            // !Send (ACP crate uses `spawn_local` internally).
            let local_set = tokio::task::LocalSet::new();
            local_set
                .run_until(async {
                    let stdin = tokio::io::stdin();
                    let stdout = tokio::io::stdout();
                    // Wrap stdout in compat (tokio → futures-io), then in
                    // FlushingWrite to auto-flush after each write (the ACP
                    // library writes lines but never calls flush()).
                    let (conn, io_task) = AgentSideConnection::new(
                        agent.clone(),
                        FlushingWrite::new(
                            tokio_util::compat::TokioAsyncWriteCompatExt::compat_write(stdout),
                        ),
                        TokioAsyncReadCompatExt::compat(stdin),
                        |fut| {
                            tokio::task::spawn_local(fut);
                        },
                    );
                    *conn_slot.lock().unwrap() = Some(conn);
                    // Spawn the I/O task on the LocalSet so that both the
                    // I/O reader and the message handler (spawned inside
                    // via the callback) are driven concurrently.
                    let handle = tokio::task::spawn_local(io_task);
                    // Block until stdin closes (EOF), which ends the session.
                    let _ = handle.await;
                    Ok::<(), anyhow::Error>(())
                })
                .await?;

            Ok::<(), anyhow::Error>(())
        })?;

        Ok(())
    }
}
