//! Concurrent async adapter for the cooperative runner.
use super::{Event, Runner};
use crate::Code;
use alloc::{boxed::Box, vec::Vec};
use core::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
};

/// Futures may borrow the host, but own their call parameters. Implementations
/// can use interior mutability to manage several simultaneous operations.
pub trait AsyncHost {
    /// Create a future for a call with owned parameters and a correlated result.
    fn call(
        &self,
        list: usize,
        component: i32,
        method: i32,
        params: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, i32>> + '_>>;
    /// Create a timer for an absolute monotonic millisecond deadline.
    fn sleep_until(&self, deadline: u64) -> Pin<Box<dyn Future<Output = ()> + '_>>;
    /// Read the monotonic clock in milliseconds.
    fn now_ms(&self) -> u64;
}

type SleepFuture<'a> = Pin<Box<dyn Future<Output = ()> + 'a>>;

struct Pending<'a> {
    token: u64,
    component: i32,
    method: i32,
    future: Pin<Box<dyn Future<Output = Result<Vec<u8>, i32>> + 'a>>,
}

/// Run until every list finishes, returning completion and failure events in
/// observation order. Dropping this future cancels outstanding host futures.
pub async fn run_async(runner: &mut Runner, host: &impl AsyncHost) -> Result<Vec<Event>, Code> {
    let mut pending: Vec<Pending<'_>> = Vec::new();
    let mut events = Vec::new();
    let mut timer: Option<(u64, SleepFuture<'_>)> = None;
    loop {
        let deadline = loop {
            match runner.poll(host.now_ms()) {
                Event::Call {
                    token,
                    list,
                    component,
                    method,
                    params,
                } => pending.push(Pending {
                    token,
                    component,
                    method,
                    future: host.call(list, component, method, params),
                }),
                event @ (Event::Complete { .. } | Event::Failed { .. }) => events.push(event),
                Event::Sleep { until_ms } => break until_ms,
                Event::Finished => return Ok(events),
            }
        };
        pending.retain(|call| runner.is_pending(call.token));
        if timer.as_ref().map(|t| t.0) != Some(deadline) {
            timer = if deadline == u64::MAX {
                None
            } else {
                Some((deadline, host.sleep_until(deadline)))
            };
        }
        let completed = poll_fn(|cx| {
            for (index, call) in pending.iter_mut().enumerate() {
                if let Poll::Ready(result) = call.future.as_mut().poll(cx) {
                    return Poll::Ready(Some((index, result)));
                }
            }
            if timer
                .as_mut()
                .is_some_and(|(_, future)| future.as_mut().poll(cx).is_ready())
            {
                return Poll::Ready(None);
            }
            Poll::Pending
        })
        .await;
        if let Some((index, result)) = completed {
            let call = pending.swap_remove(index);
            match runner.resume_at(
                host.now_ms(),
                call.token,
                call.component,
                call.method,
                result.as_deref().map_err(|e| *e),
            ) {
                Ok(()) | Err(Code::NotFound) => {} // The deadline may have expired.
                Err(error) => return Err(error),
            }
        } else {
            timer = None;
        }
    }
}
