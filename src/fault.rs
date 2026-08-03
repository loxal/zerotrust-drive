// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Deterministic durability fault injection for v2 transactions.
//!
//! Production builds only execute the checkpoints. Tests can arrange for the
//! Nth checkpoint on the current thread to return an injected-crash error,
//! then reopen the store and exercise recovery from that exact boundary.

use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DurabilityEvent {
    Write,
    FileSync,
    Rename,
    DirectorySync,
    Cleanup,
    Recovery,
}

const INJECTED_CRASH: &str = "deterministic injected crash";

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DurabilityCheckpoint {
    pub(crate) event: DurabilityEvent,
    pub(crate) context: String,
}

pub(crate) fn checkpoint(event: DurabilityEvent, context: &str) -> io::Result<()> {
    #[cfg(test)]
    {
        test_state::STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.checkpoints.push(DurabilityCheckpoint {
                event,
                context: context.to_string(),
            });
            let checkpoint = state.checkpoints.len();
            match &state.action {
                Some(test_state::Action::FailAt(expected)) if *expected == checkpoint => {
                    return Err(io::Error::other(format!(
                        "{INJECTED_CRASH} after {event:?}: {context}"
                    )));
                }
                #[cfg(unix)]
                Some(test_state::Action::KillAt {
                    checkpoint: expected_checkpoint,
                    expected,
                }) if *expected_checkpoint == checkpoint => {
                    assert_eq!(
                        expected.event, event,
                        "subprocess crash checkpoint {checkpoint} event changed"
                    );
                    assert_eq!(
                        expected.context, context,
                        "subprocess crash checkpoint {checkpoint} context changed"
                    );
                    use std::io::Write as _;
                    let mut stderr = std::io::stderr().lock();
                    writeln!(
                        stderr,
                        "ZDRIVE_SIGKILL_CHECKPOINT\t{checkpoint}\t{event:?}\t{context}"
                    )
                    .expect("write subprocess crash marker");
                    stderr.flush().expect("flush subprocess crash marker");
                    drop(stderr);
                    let result = unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
                    assert_eq!(result, 0, "send deterministic SIGKILL to test process");
                    unreachable!("SIGKILL returned without terminating the test process");
                }
                _ => {}
            }
            Ok(())
        })
    }

    #[cfg(not(test))]
    {
        let _ = (event, context);
        Ok(())
    }
}

pub(crate) fn is_injected_crash(error: &io::Error) -> bool {
    error.to_string().starts_with(INJECTED_CRASH)
}

#[cfg(test)]
pub(crate) struct FaultInjectionGuard;

#[cfg(test)]
impl FaultInjectionGuard {
    pub(crate) fn fail_at(checkpoint: usize) -> Self {
        test_state::STATE.with(|state| {
            *state.borrow_mut() = test_state::State {
                action: Some(test_state::Action::FailAt(checkpoint)),
                checkpoints: Vec::new(),
            };
        });
        Self
    }

    pub(crate) fn record() -> Self {
        test_state::STATE.with(|state| {
            *state.borrow_mut() = test_state::State {
                action: None,
                checkpoints: Vec::new(),
            };
        });
        Self
    }

    pub(crate) fn events(&self) -> Vec<DurabilityEvent> {
        test_state::STATE.with(|state| {
            state
                .borrow()
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.event)
                .collect()
        })
    }

    pub(crate) fn checkpoints(&self) -> Vec<DurabilityCheckpoint> {
        test_state::STATE.with(|state| state.borrow().checkpoints.clone())
    }

    #[cfg(unix)]
    pub(crate) fn kill_at(checkpoint: usize, expected: DurabilityCheckpoint) -> Self {
        test_state::STATE.with(|state| {
            *state.borrow_mut() = test_state::State {
                action: Some(test_state::Action::KillAt {
                    checkpoint,
                    expected,
                }),
                checkpoints: Vec::new(),
            };
        });
        Self
    }
}

#[cfg(test)]
impl Drop for FaultInjectionGuard {
    fn drop(&mut self) {
        test_state::STATE.with(|state| *state.borrow_mut() = test_state::State::default());
    }
}

#[cfg(test)]
mod test_state {
    use super::DurabilityCheckpoint;
    use std::cell::RefCell;

    pub(super) enum Action {
        FailAt(usize),
        #[cfg(unix)]
        KillAt {
            checkpoint: usize,
            expected: DurabilityCheckpoint,
        },
    }

    #[derive(Default)]
    pub(super) struct State {
        pub(super) action: Option<Action>,
        pub(super) checkpoints: Vec<DurabilityCheckpoint>,
    }

    thread_local! {
        pub(super) static STATE: RefCell<State> = RefCell::new(State::default());
    }
}
