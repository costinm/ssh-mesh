#![cfg(feature = "program-host")]

use micro_cel::{
    Code,
    host::translate::{Schema, translate},
    program::{
        Event, Program, ProgramLimits, Rule, RuleList, Runner,
        async_runtime::{AsyncHost, run_async},
    },
};
use std::{
    cell::{Cell, RefCell},
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll, Waker},
};

#[derive(Default)]
struct Host {
    now: Cell<u64>,
    calls: RefCell<Vec<(usize, i32)>>,
    results: RefCell<Vec<(i32, Vec<u8>)>>,
    waker: RefCell<Option<Waker>>,
}
impl Host {
    fn complete(&self, method: i32, value: u8) {
        self.results.borrow_mut().push((method, vec![value]));
        self.wake();
    }
    fn advance(&self, time: u64) {
        self.now.set(time);
        self.wake();
    }
    fn wake(&self) {
        if let Some(w) = self.waker.borrow_mut().take() {
            w.wake();
        }
    }
}
impl AsyncHost for Host {
    fn call(
        &self,
        list: usize,
        _: i32,
        method: i32,
        _: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, i32>> + '_>> {
        self.calls.borrow_mut().push((list, method));
        Box::pin(std::future::poll_fn(move |cx| {
            let mut results = self.results.borrow_mut();
            if let Some(i) = results.iter().position(|(m, _)| *m == method) {
                Poll::Ready(Ok(results.remove(i).1))
            } else {
                *self.waker.borrow_mut() = Some(cx.waker().clone());
                Poll::Pending
            }
        }))
    }
    fn sleep_until(&self, deadline: u64) -> Pin<Box<dyn Future<Output = ()> + '_>> {
        Box::pin(std::future::poll_fn(move |cx| {
            if self.now.get() >= deadline {
                Poll::Ready(())
            } else {
                *self.waker.borrow_mut() = Some(cx.waker().clone());
                Poll::Pending
            }
        }))
    }
    fn now_ms(&self) -> u64 {
        self.now.get()
    }
}
fn list(name: &str, rules: Vec<Rule>) -> RuleList {
    RuleList {
        name: name.into(),
        context: vec![0xa0],
        rules,
    }
}
fn eval(s: &str) -> Rule {
    Rule::Eval {
        expr: translate(s, &Schema::parse("x=1").unwrap()).unwrap(),
    }
}
fn poll<F: Future>(f: Pin<&mut F>) -> Poll<F::Output> {
    let w = Waker::noop();
    f.poll(&mut Context::from_waker(w))
}

#[test]
fn independent_calls_are_polled_and_do_not_replay() {
    let host = Rc::new(Host::default());
    let mut runner = Runner::new(
        Program {
            lists: vec![
                list("a", vec![eval("call(1, 1, {})")]),
                list("b", vec![eval("call(1, 2, {})"), eval("call(1, 3, {})")]),
            ],
        },
        ProgramLimits::default(),
    )
    .unwrap();
    let mut task = Box::pin(run_async(&mut runner, &*host));
    assert!(poll(task.as_mut()).is_pending());
    assert_eq!(&*host.calls.borrow(), &[(0, 1), (1, 2)]);
    host.complete(2, 2);
    assert!(poll(task.as_mut()).is_pending());
    assert_eq!(&*host.calls.borrow(), &[(0, 1), (1, 2), (1, 3)]);
    host.complete(3, 3);
    assert!(poll(task.as_mut()).is_pending());
    host.complete(1, 1);
    let Poll::Ready(Ok(events)) = poll(task.as_mut()) else {
        panic!("not finished")
    };
    assert_eq!(
        events,
        vec![
            Event::Complete {
                list: 1,
                result: vec![3]
            },
            Event::Complete {
                list: 0,
                result: vec![1]
            }
        ]
    );
    assert_eq!(host.calls.borrow().len(), 3);
}

#[test]
fn timer_and_timeout_progress_while_call_is_pending() {
    let host = Host::default();
    let limits = ProgramLimits {
        timeout_ms: 10,
        ..ProgramLimits::default()
    };
    let mut runner = Runner::new(
        Program {
            lists: vec![
                list("a", vec![eval("call(1, 1, {})")]),
                list("b", vec![Rule::After { delay_ms: 5 }, eval("7")]),
            ],
        },
        limits,
    )
    .unwrap();
    let mut task = Box::pin(run_async(&mut runner, &host));
    assert!(poll(task.as_mut()).is_pending());
    host.advance(5);
    assert!(poll(task.as_mut()).is_pending());
    host.advance(10);
    let Poll::Ready(Ok(events)) = poll(task.as_mut()) else {
        panic!("not finished")
    };
    assert_eq!(
        events,
        vec![
            Event::Complete {
                list: 1,
                result: vec![7]
            },
            Event::Failed {
                list: 0,
                error: Code::Invoke(-110)
            }
        ]
    );
    assert_eq!(host.calls.borrow().len(), 1);
}
