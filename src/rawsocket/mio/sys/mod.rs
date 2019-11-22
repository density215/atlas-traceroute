//! Module with system specific types.
//!
//! `Event`: a type alias for the system specific event, e.g.
//!          `kevent` or `epoll_event`.
//! `event`: a module with various helper functions for `Event`, see
//!          `crate::event::Event` for the required functions.
#[cfg(unix)]
pub use unix::RawSocket;

#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
mod windows;
