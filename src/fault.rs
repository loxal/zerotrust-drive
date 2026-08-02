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

pub(crate) fn checkpoint(event: DurabilityEvent, context: &str) -> io::Result<()> {
    #[cfg(test)]
    {
        test_state::STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.events.push(event);
            if state.fail_at == Some(state.events.len()) {
                return Err(io::Error::other(format!(
                    "{INJECTED_CRASH} after {event:?}: {context}"
                )));
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
                fail_at: Some(checkpoint),
                events: Vec::new(),
            };
        });
        Self
    }

    pub(crate) fn record() -> Self {
        test_state::STATE.with(|state| {
            *state.borrow_mut() = test_state::State {
                fail_at: None,
                events: Vec::new(),
            };
        });
        Self
    }

    pub(crate) fn events(&self) -> Vec<DurabilityEvent> {
        test_state::STATE.with(|state| state.borrow().events.clone())
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
    use super::DurabilityEvent;
    use std::cell::RefCell;

    #[derive(Default)]
    pub(super) struct State {
        pub(super) fail_at: Option<usize>,
        pub(super) events: Vec<DurabilityEvent>,
    }

    thread_local! {
        pub(super) static STATE: RefCell<State> = RefCell::new(State::default());
    }
}
