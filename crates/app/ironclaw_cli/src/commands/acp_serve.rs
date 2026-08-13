//! ACP (Agent Client Protocol) server: speaks ACP on stdio, drives the
//! Reborn runtime for each prompt.
//!
//! Usage: `ironclaw acp-serve [--cwd <dir>]`
//!
//! ## Architecture
//!
//! Unlike the HTTP `serve` command (WebChat), this command:
//! - Implements the `agent_client_protocol::Agent` trait on stdio
//! - Bridges each ACP `prompt()` call to `RebornRuntime::send_user_message()`
//! - Maintains per-session conversation state so multi-turn conversations work
//! - Returns the assistant reply text in the `PromptResponse`
//!
//! The runtime boots identically to the `run` command (multi_thread tokio).
//! ACP I/O runs on a `LocalSet` inside the multi_thread runtime so the
//! !Send `Agent` trait impl works.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use std::pin::Pin;

use agent_client_protocol::{
    Agent, AgentSideConnection, AgentCapabilities, AuthenticateRequest, AuthenticateResponse,
    Client, ContentBlock, ContentChunk, Error, Implementation, InitializeRequest,
    InitializeResponse, NewSessionRequest, NewSessionResponse, PromptRequest, PromptResponse,
    ProtocolVersion, SessionId, SessionNotification, SessionUpdate, StopReason,
};
use clap::Args;
use ironclaw_composition::{ConversationId, RebornRuntime, TurnStatus, build_reborn_runtime};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;

use anyhow::Context as _;

use crate::context::RebornCliContext;
use crate::runtime::{
    RuntimeInputCaller, RuntimeInputOptions, build_runtime_input_with_options,
};

// ── CLI Args ───────────────────────────────────────────────────────────────

#[derive(Debug, Args)]
pub(crate) struct AcpServeCommand {
    /// Working directory for the agent.
    #[arg(long)]
    cwd: Option<String>,
}

// ── ACP Agent trait implementation ─────────────────────────────────────────

/// Per-session mutable state: maps ACP session IDs to Reborn conversation IDs
/// and per-session cancellation tokens.
///
/// Uses `RefCell` because the `Agent` trait is `!Send` — all access happens
/// on the `LocalSet`, so interior mutability without thread safety is correct.
struct SessionState {
    conversations: RefCell<HashMap<String, ConversationId>>,
    cancel_tokens: RefCell<HashMap<String, CancellationToken>>,
}

impl SessionState {
    fn new() -> Self {
        Self {
            conversations: RefCell::new(HashMap::new()),
            cancel_tokens: RefCell::new(HashMap::new()),
        }
    }

    /// Create a new conversation for the given session ID, returning the
    /// session ID to use in the response.
    fn create_session(&self) -> String {
        let sid = uuid::Uuid::new_v4().to_string();
        // Reserve the entry so the session exists even before the first prompt.
        // The conversation is created lazily on first prompt so we don't need
        // async access here.
        self.cancel_tokens.borrow_mut().insert(sid.clone(), CancellationToken::new());
        sid
    }

    /// Get or create a per-session cancellation token.
    fn cancel_token_for(&self, session_id: &str) -> CancellationToken {
        let mut tokens = self.cancel_tokens.borrow_mut();
        tokens
            .entry(session_id.to_string())
            .or_insert_with(CancellationToken::new)
            .clone()
    }

    /// Cancel the token for a session and replace it with a fresh one so
    /// future prompts in the same session are not pre-cancelled.
    fn cancel_session(&self, session_id: &str) {
        let mut tokens = self.cancel_tokens.borrow_mut();
        if let Some(token) = tokens.get(session_id) {
            token.cancel();
        }
        tokens.insert(session_id.to_string(), CancellationToken::new());
    }
}

struct RebornAcpAgent {
    runtime: Arc<RebornRuntime>,
    conn: Arc<std::sync::Mutex<Option<AgentSideConnection>>>,
    sessions: Arc<SessionState>,
}

impl Clone for RebornAcpAgent {
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
            conn: self.conn.clone(),
            sessions: self.sessions.clone(),
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
            InitializeResponse::new(ProtocolVersion::from(1u16))
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
        let sid = self.sessions.create_session();
        Ok(NewSessionResponse::new(SessionId::new(sid)))
    }

    async fn prompt(
        &self,
        args: PromptRequest,
    ) -> std::result::Result<PromptResponse, Error> {
        let session_id: &str = &args.session_id.0;

        let content: Vec<String> = args
            .prompt
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.text.clone()),
                ContentBlock::ResourceLink(r) => {
                    tracing::warn!(
                        "ACP ResourceLink block received (uri: {:?}) — not supported, \
                         skipping. Only text content is bridged to the Reborn runtime.",
                        r.uri,
                    );
                    None
                }
                other => {
                    tracing::debug!(
                        "ACP ContentBlock variant {:?} not supported — skipping.",
                        std::mem::discriminant(other),
                    );
                    None
                }
            })
            .collect();

        let content = content.join("\n");
        if content.is_empty() {
            return Err(Error::invalid_params());
        }

        // Look up or create a conversation for this session.
        let conversation = {
            let convs = self.sessions.conversations.borrow_mut();
            match convs.get(session_id) {
                Some(id) => id.clone(),
                None => {
                    // Drop the borrow before the async call.
                    drop(convs);
                    let id = self
                        .runtime
                        .new_conversation()
                        .await
                        .map_err(|e| Error::new(-32603, format!("Failed to create conversation: {e}")))?;
                    self.sessions.conversations.borrow_mut().insert(session_id.to_string(), id.clone());
                    id
                }
            }
        };

        // Per-session cancellation token.
        let cancel_token = self.sessions.cancel_token_for(session_id);

        let reply = self
            .runtime
            .send_user_message_with_cancellation(&conversation, &content, cancel_token)
            .await
            .map_err(|e| Error::new(-32603, format!("Agent run failed: {e}")))?;

        let stop_reason = if reply.status == TurnStatus::Cancelled {
            StopReason::Cancelled
        } else if reply.is_successful_final_reply() {
            StopReason::EndTurn
        } else {
            StopReason::MaxTurnRequests
        };

        // Stream the assistant reply text back as an AgentMessageChunk
        // notification so the client receives the content.
        if let Some(text) = &reply.text {
            // NOTE: The MutexGuard is held across the `.await` here.
            // This is safe because all code runs on a `LocalSet` (single-
            // threaded), so the `!Send` MutexGuard cannot be sent across
            // threads. The AgentSideConnection is not Clone, so we cannot
            // extract it before the await.
            if let Some(conn) = self.conn.lock().unwrap().as_ref() {
                let _ = conn
                    .session_notification(
                        SessionNotification::new(
                            args.session_id,
                            SessionUpdate::AgentMessageChunk(
                                ContentChunk::new(ContentBlock::from(text.as_str())),
                            ),
                        ),
                    )
                    .await;
            }
        }

        Ok(PromptResponse::new(stop_reason))
    }

    async fn cancel(
        &self,
        args: agent_client_protocol::CancelNotification,
    ) -> std::result::Result<(), Error> {
        let session_id: &str = &args.session_id.0;
        self.sessions.cancel_session(session_id);
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
                sessions: Arc::new(SessionState::new()),
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

            // Shut down the runtime after the LocalSet (and all ACP I/O)
            // completes. This drains background tasks (turn scheduler,
            // trigger poller, credential refresh worker, etc.) following
            // the same pattern as the `serve` command in serve.rs.
            eprintln!("[ACP] shutting down runtime...");
            match Arc::try_unwrap(runtime) {
                Ok(r) => r.shutdown().await.context("Reborn runtime shutdown failed")?,
                Err(_) => {
                    // Arc refs remain from the agent struct that was dropped
                    // with the LocalSet. This should not happen, but if it
                    // does, we log a warning — the runtime's Drop will still
                    // clean up internal state, just without graceful drain.
                    tracing::warn!(
                        "[ACP] runtime Arc still has multiple refs at shutdown; \
                         skipping graceful shutdown. Background tasks may not drain."
                    );
                }
            }

            Ok::<(), anyhow::Error>(())
        })?;

        Ok(())
    }
}
