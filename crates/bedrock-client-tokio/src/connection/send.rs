// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! One prepared accepted-Nether effect, retained on the original codec/cipher owner.

use super::Connection;
use bytes::Bytes;
use futures::future::BoxFuture;
use nethernet_tokio::{SendPermit, session::Channel};
use std::{io, sync::Arc, time::Instant, vec::IntoIter};

/// The original effect's local admission result after new sends have been sealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    /// No prepared effect existed.
    Idle,
    /// Every original message received its successful local core admission receipt.
    Complete,
    /// An uncommitted remainder was discarded; no complete-effect receipt is promised.
    Incomplete,
}

pub(super) struct PendingSend {
    deadline: Instant,
    messages: IntoIter<Bytes>,
    phase: Phase,
    failure: Option<Arc<io::Error>>,
    discarded: bool,
}

enum Phase {
    NeedCapacity,
    Reserving(BoxFuture<'static, io::Result<SendPermit>>),
    Reserved(SendPermit),
    Receipt(BoxFuture<'static, io::Result<()>>),
    Complete,
    Stopped,
}

pub(super) struct RetirementState {
    deadline: Instant,
    outcome: Option<SendOutcome>,
}

impl Connection {
    /// Moves the original encoded messages into the sole retained send slot.
    pub fn prepare_send(&mut self, body: Bytes, deadline: Instant) -> io::Result<()> {
        self.ensure_send_idle()?;
        check_deadline(deadline)?;
        drop(self.transport.accepted_sender()?);
        let messages = self.encode_body(body)?.into_iter();
        let phase = if messages.as_slice().is_empty() {
            Phase::Complete
        } else {
            Phase::NeedCapacity
        };
        self.pending_send = Some(PendingSend {
            deadline,
            messages,
            phase,
            failure: None,
            discarded: false,
        });
        Ok(())
    }

    /// Borrows the first absolute cutoff without replacing any operation state.
    pub fn prepared_deadline(&self) -> io::Result<Instant> {
        Ok(self
            .pending_send
            .as_ref()
            .ok_or_else(|| invalid("no native accepting send is retained"))?
            .deadline)
    }

    /// Settles the exact previous receipt, then reserves one original actor command slot.
    pub async fn next_send_capacity(&mut self) -> io::Result<bool> {
        loop {
            let pending = self
                .pending_send
                .as_mut()
                .ok_or_else(|| invalid("no native accepting send is retained"))?;
            if let Some(error) = &pending.failure {
                return Err(repeat(error));
            }
            if matches!(pending.phase, Phase::Complete) {
                return Ok(false);
            }
            if self.send_sealed {
                return Err(closed());
            }
            let deadline = pending.deadline;
            if let Err(error) = check_deadline(deadline) {
                return Err(self.fail_send(error));
            }
            match &mut pending.phase {
                Phase::NeedCapacity => {
                    if pending.messages.as_slice().is_empty() {
                        pending.phase = Phase::Complete;
                        continue;
                    }
                    let sender = self.transport.accepted_sender()?;
                    pending.phase = Phase::Reserving(Box::pin(async move {
                        sender
                            .reserve_send(Some(deadline))
                            .await
                            .map_err(io::Error::other)
                    }));
                }
                Phase::Reserving(reservation) => {
                    let result = tokio::time::timeout_at(
                        deadline.into(),
                        self.transport.progress_accepted(reservation.as_mut()),
                    )
                    .await;
                    match result {
                        Ok(Ok(Ok(permit))) => pending.phase = Phase::Reserved(permit),
                        Ok(Ok(Err(error))) => {
                            pending.phase = Phase::Stopped;
                            return Err(self.fail_send(error));
                        }
                        Ok(Err(error)) => return Err(self.fail_send(error)),
                        Err(_) => return Err(self.fail_send(expired())),
                    }
                }
                Phase::Reserved(_) => return Ok(true),
                Phase::Receipt(receipt) => {
                    let result = tokio::time::timeout_at(
                        deadline.into(),
                        self.transport.progress_accepted(receipt.as_mut()),
                    )
                    .await;
                    match result {
                        Ok(Ok(Ok(()))) => {
                            pending.phase = if pending.messages.as_slice().is_empty() {
                                Phase::Complete
                            } else {
                                Phase::NeedCapacity
                            };
                            if let Err(error) = check_deadline(deadline) {
                                return Err(self.fail_send(error));
                            }
                        }
                        Ok(Ok(Err(error))) => {
                            pending.phase = Phase::Stopped;
                            return Err(self.fail_send(error));
                        }
                        Ok(Err(error)) => return Err(self.fail_send(error)),
                        Err(_) => return Err(self.fail_send(expired())),
                    }
                }
                Phase::Complete => return Ok(false),
                Phase::Stopped => return Err(closed()),
            }
        }
    }

    /// Reborrows only a retained granted permit, preserving its original deadline and failure.
    pub fn reserved_send_capacity(&mut self) -> io::Result<()> {
        if self.send_sealed {
            return Err(closed());
        }
        let pending = self
            .pending_send
            .as_mut()
            .ok_or_else(|| invalid("no native accepting send is retained"))?;
        if let Some(error) = &pending.failure {
            return Err(repeat(error));
        }
        if let Err(error) = check_deadline(pending.deadline) {
            return Err(self.fail_send(error));
        }
        if !matches!(pending.phase, Phase::Reserved(_)) {
            return Err(invalid("native accepting send has no capacity"));
        }
        Ok(())
    }

    /// Encrypts once and synchronously commits the retained permit; its receipt stays owned here.
    pub fn commit_send_capacity(&mut self) -> io::Result<()> {
        self.reserved_send_capacity()?;
        let pending = self.pending_send.as_mut().expect("checked retained effect");
        let Phase::Reserved(permit) = std::mem::replace(&mut pending.phase, Phase::Stopped) else {
            unreachable!("checked retained permit")
        };
        let message = pending
            .messages
            .next()
            .expect("reserved capacity has one original message");
        let result = self.encrypt_message(message).and_then(|message| {
            permit
                .commit(Channel::Reliable, message)
                .map_err(io::Error::other)
        });
        match result {
            Ok(receipt) => {
                self.pending_send
                    .as_mut()
                    .expect("one retained effect")
                    .phase = Phase::Receipt(Box::pin(async move {
                    receipt.acknowledged().await.map_err(io::Error::other)
                }));
                Ok(())
            }
            Err(error) => Err(self.fail_send(error)),
        }
    }

    /// Releases only a fully acknowledged original effect, including after local sealing.
    pub fn finish_send(&mut self) -> io::Result<()> {
        let pending = self
            .pending_send
            .as_ref()
            .ok_or_else(|| invalid("no native accepting send is retained"))?;
        if let Some(error) = &pending.failure {
            return Err(repeat(error));
        }
        if !matches!(pending.phase, Phase::Complete) {
            return Err(invalid("native accepting send is incomplete"));
        }
        self.pending_send = None;
        Ok(())
    }

    /// Seals local commits and discards only work that has not reached synchronous commit.
    pub fn retire_send(&mut self, deadline: Instant) {
        self.send_sealed = true;
        if self.send_retirement.is_some() {
            return;
        }
        let deadline = self
            .pending_send
            .as_ref()
            .map_or(deadline, |pending| pending.deadline.min(deadline));
        let outcome = match self.pending_send.as_mut() {
            None => Some(SendOutcome::Idle),
            Some(pending) if matches!(pending.phase, Phase::Complete) => {
                Some(SendOutcome::Complete)
            }
            Some(pending) => {
                pending.discarded |= !pending.messages.as_slice().is_empty();
                pending.messages = Vec::new().into_iter();
                if matches!(pending.phase, Phase::Receipt(_)) {
                    None
                } else {
                    pending.discarded = true;
                    pending.phase = Phase::Stopped;
                    Some(SendOutcome::Incomplete)
                }
            }
        };
        self.send_retirement = Some(RetirementState { deadline, outcome });
    }

    /// Finishes only the original committed receipt under the first cleanup cutoff.
    pub async fn settle_send(&mut self) -> io::Result<SendOutcome> {
        loop {
            let retirement = self
                .send_retirement
                .as_ref()
                .ok_or_else(|| invalid("native accepting send is not retiring"))?;
            if let Some(outcome) = retirement.outcome {
                if let Some(error) = self
                    .pending_send
                    .as_ref()
                    .and_then(|pending| pending.failure.as_ref())
                {
                    return Err(repeat(error));
                }
                return Ok(outcome);
            }
            let deadline = retirement.deadline;
            if check_deadline(deadline).is_err() {
                self.pending_send
                    .as_mut()
                    .expect("retiring committed effect")
                    .phase = Phase::Stopped;
                self.send_retirement
                    .as_mut()
                    .expect("first retirement")
                    .outcome = Some(SendOutcome::Incomplete);
                return Err(self.fail_send(expired()));
            }
            let pending = self
                .pending_send
                .as_mut()
                .expect("retiring committed effect");
            let Phase::Receipt(receipt) = &mut pending.phase else {
                unreachable!("only an original receipt remains during settlement")
            };
            let result = tokio::time::timeout_at(
                deadline.into(),
                self.transport.settle_accepted(receipt.as_mut()),
            )
            .await;
            match result {
                Ok(Ok(Ok(()))) => {
                    pending.phase = Phase::Stopped;
                    if let Err(error) = check_deadline(deadline) {
                        self.send_retirement
                            .as_mut()
                            .expect("first retirement")
                            .outcome = Some(SendOutcome::Incomplete);
                        return Err(self.fail_send(error));
                    }
                    let outcome = if pending.discarded {
                        SendOutcome::Incomplete
                    } else {
                        SendOutcome::Complete
                    };
                    pending.phase = if pending.discarded {
                        Phase::Stopped
                    } else {
                        Phase::Complete
                    };
                    self.send_retirement
                        .as_mut()
                        .expect("first retirement")
                        .outcome = Some(outcome);
                }
                Ok(Ok(Err(error))) => {
                    pending.phase = Phase::Stopped;
                    self.send_retirement
                        .as_mut()
                        .expect("first retirement")
                        .outcome = Some(SendOutcome::Incomplete);
                    return Err(self.fail_send(error));
                }
                Ok(Err(error)) => {
                    drop(self.fail_send(error));
                }
                Err(_) => {
                    pending.phase = Phase::Stopped;
                    self.send_retirement
                        .as_mut()
                        .expect("first retirement")
                        .outcome = Some(SendOutcome::Incomplete);
                    return Err(self.fail_send(expired()));
                }
            }
        }
    }

    /// Caches the first cause without replacing a pending receipt or admitting new output.
    fn fail_send(&mut self, error: io::Error) -> io::Error {
        self.send_sealed = true;
        let pending = self
            .pending_send
            .as_mut()
            .expect("failure belongs to retained effect");
        repeat(pending.failure.get_or_insert_with(|| Arc::new(error)))
    }
}

/// Uses the same native adapter clock as the original Nether command admission.
fn check_deadline(deadline: Instant) -> io::Result<()> {
    if tokio::time::Instant::now().into_std() >= deadline {
        Err(expired())
    } else {
        Ok(())
    }
}

/// Repeats the original error class and cause without duplicating payload state.
fn repeat(error: &Arc<io::Error>) -> io::Error {
    io::Error::new(error.kind(), Arc::clone(error))
}

/// Reports an invalid local phase without exposing packet or identity data.
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Reports local send retirement without inspecting remote application state.
fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "native accepting send is sealed",
    )
}

/// Preserves the first finite operation cutoff.
fn expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "native accepting send deadline expired",
    )
}

/// Borrowed progress for one original encoded effect. Dropping it retains that exact progress.
#[must_use = "drive or explicitly retire the original retained send"]
pub struct PreparedSend<'a> {
    connection: &'a mut Connection,
}

/// A borrowed original queue permit; check application authority immediately before commit.
#[must_use = "commit after checking current authority, or retain the original effect"]
pub struct SendCapacity<'a> {
    connection: &'a mut Connection,
}

/// Local commits are sealed; only the same already committed receipt can finish.
#[must_use = "settle the original receipt before transport retirement"]
pub struct SendRetirement<'a> {
    connection: &'a mut Connection,
}

impl Connection {
    /// Encodes once without cipher progress, then borrows the same retained operation.
    pub fn prepare_body(&mut self, body: Bytes, deadline: Instant) -> io::Result<PreparedSend<'_>> {
        self.prepare_send(body, deadline)?;
        Ok(PreparedSend { connection: self })
    }
    /// Reborrows the original effect without reserving capacity or changing cipher state.
    pub fn resume_send(&mut self) -> io::Result<PreparedSend<'_>> {
        self.prepared_deadline()?;
        Ok(PreparedSend { connection: self })
    }
    /// Seals local commits while preserving the first cleanup cutoff and committed receipt.
    pub fn begin_send_retirement(&mut self, deadline: Instant) -> SendRetirement<'_> {
        self.retire_send(deadline);
        SendRetirement { connection: self }
    }
}

impl PreparedSend<'_> {
    /// The first original capacity/admission cutoff, unchanged by cancellation.
    pub fn deadline(&self) -> Instant {
        self.connection
            .prepared_deadline()
            .expect("borrowed send retains its effect")
    }
    /// Settles the previous receipt and borrows the next queue permit.
    /// Keep the application grant check and synchronous commit adjacent, without awaiting.
    pub async fn next(&mut self) -> io::Result<Option<SendCapacity<'_>>> {
        if self.connection.next_send_capacity().await? {
            Ok(Some(SendCapacity {
                connection: self.connection,
            }))
        } else {
            Ok(None)
        }
    }
    /// Reborrows the same already granted permit after an owned I/O handoff.
    pub fn reserved_capacity(&mut self) -> io::Result<SendCapacity<'_>> {
        self.connection.reserved_send_capacity()?;
        Ok(SendCapacity {
            connection: self.connection,
        })
    }
    /// Releases only a completed effect after its caller's continuation obligation.
    pub fn finish(self) -> io::Result<()> {
        self.connection.finish_send()
    }
}
impl SendCapacity<'_> {
    /// Advances the sole cipher and commits this original permit without yielding.
    pub fn commit(self) -> io::Result<()> {
        self.connection.commit_send_capacity()
    }
}
impl SendRetirement<'_> {
    /// Settles only the original committed output under its first cleanup cutoff.
    /// Complete proves local admission, not remote processing.
    pub async fn finish(&mut self) -> io::Result<SendOutcome> {
        self.connection.settle_send().await
    }
}
