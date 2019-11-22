use super::net::{new_ip_socket, socket_addr};
use mio::event::Evented;
use mio::sys::unix::uio::VecIo;
use mio::unix::EventedFd;
use mio::{Poll, PollOpt, Ready, Token};
use socket2::{self, SockAddr, Socket};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

// #[allow(unused_imports)] // only here for Rust 1.8
// use net2::RawSocketExt;
use iovec::IoVec;

pub struct RawSocket {
    io: socket2::Socket,
}

impl RawSocket {
    pub fn new(socket: socket2::Socket) -> std::io::Result<RawSocket> {
        socket.set_nonblocking(true)?;
        Ok(RawSocket { io: socket })
    }

    pub fn bind(addr: SocketAddr) -> std::io::Result<RawSocket> {
        // Gives a warning for non Apple platforms.
        #[allow(clippy::let_and_return)]
        let socket = new_ip_socket(addr, libc::SOCK_RAW);

        // Set SO_NOSIGPIPE on iOS and macOS (mirrors what libstd does).
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        let socket = socket.and_then(|socket| {
            syscall!(setsockopt(
                socket,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &1 as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ))
            .map(|_| socket)
        });

        socket.and_then(|socket| {
            let (raw_addr, raw_addr_length) = socket_addr(&addr);
            syscall!(bind(socket, raw_addr, raw_addr_length))
                .map_err(|err| {
                    // Close the socket if we hit an error, ignoring the error
                    // from closing since we can't pass back two errors.
                    let _ = unsafe { libc::close(socket) };
                    err
                })
                .map(|_| RawSocket {
                    io: unsafe { Socket::from_raw_fd(socket) },
                })
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(SocketAddr::from(
            self.io.local_addr().unwrap().as_inet().unwrap(),
        ))
    }

    pub fn try_clone(&self) -> std::io::Result<RawSocket> {
        self.io.try_clone().map(|io| RawSocket { io })
    }

    pub fn send_to(&self, buf: &[u8], target: &SocketAddr) -> std::io::Result<usize> {
        self.io.send_to(buf, &SockAddr::from(target.clone()))
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SockAddr)> {
        // let bla = self.io.recv_from(buf).unwrap();
        // Ok((bla.0, std::net::SocketAddr::V4(bla.1.as_inet().unwrap())))
        self.io.recv_from(buf)
    }

    pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.io.send(buf)
    }

    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.io.recv(buf)
    }

    pub fn connect(&self, addr: SocketAddr) -> std::io::Result<()> {
        self.io.connect(&SockAddr::from(addr.clone()))
    }

    pub fn broadcast(&self) -> std::io::Result<bool> {
        self.io.broadcast()
    }

    pub fn set_broadcast(&self, on: bool) -> std::io::Result<()> {
        self.io.set_broadcast(on)
    }

    pub fn multicast_loop_v4(&self) -> std::io::Result<bool> {
        self.io.multicast_loop_v4()
    }

    pub fn set_multicast_loop_v4(&self, on: bool) -> std::io::Result<()> {
        self.io.set_multicast_loop_v4(on)
    }

    pub fn multicast_ttl_v4(&self) -> std::io::Result<u32> {
        self.io.multicast_ttl_v4()
    }

    pub fn set_multicast_ttl_v4(&self, ttl: u32) -> std::io::Result<()> {
        self.io.set_multicast_ttl_v4(ttl)
    }

    pub fn multicast_loop_v6(&self) -> std::io::Result<bool> {
        self.io.multicast_loop_v6()
    }

    pub fn set_multicast_loop_v6(&self, on: bool) -> std::io::Result<()> {
        self.io.set_multicast_loop_v6(on)
    }

    pub fn ttl(&self) -> std::io::Result<u32> {
        self.io.ttl()
    }

    pub fn set_ttl(&self, ttl: u32) -> std::io::Result<()> {
        self.io.set_ttl(ttl)
    }

    pub fn join_multicast_v4(
        &self,
        multiaddr: &Ipv4Addr,
        interface: &Ipv4Addr,
    ) -> std::io::Result<()> {
        self.io.join_multicast_v4(multiaddr, interface)
    }

    pub fn join_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> std::io::Result<()> {
        self.io.join_multicast_v6(multiaddr, interface)
    }

    pub fn leave_multicast_v4(
        &self,
        multiaddr: &Ipv4Addr,
        interface: &Ipv4Addr,
    ) -> std::io::Result<()> {
        self.io.leave_multicast_v4(multiaddr, interface)
    }

    pub fn leave_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> std::io::Result<()> {
        self.io.leave_multicast_v6(multiaddr, interface)
    }

    pub fn set_only_v6(&self, only_v6: bool) -> std::io::Result<()> {
        self.io.set_only_v6(only_v6)
    }

    pub fn only_v6(&self) -> std::io::Result<bool> {
        self.io.only_v6()
    }

    pub fn take_error(&self) -> std::io::Result<Option<std::io::Error>> {
        self.io.take_error()
    }

    pub fn readv(&self, bufs: &mut [&mut IoVec]) -> std::io::Result<usize> {
        self.io.readv(bufs)
    }

    pub fn writev(&self, bufs: &[&IoVec]) -> std::io::Result<usize> {
        self.io.writev(bufs)
    }
}

impl Evented for RawSocket {
    fn register(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> std::io::Result<()> {
        EventedFd(&self.as_raw_fd()).register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> std::io::Result<()> {
        EventedFd(&self.as_raw_fd()).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> std::io::Result<()> {
        EventedFd(&self.as_raw_fd()).deregister(poll)
    }
}

impl fmt::Debug for RawSocket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.io, f)
    }
}

impl FromRawFd for RawSocket {
    unsafe fn from_raw_fd(fd: RawFd) -> RawSocket {
        RawSocket {
            io: socket2::Socket::from_raw_fd(fd),
        }
    }
}

impl IntoRawFd for RawSocket {
    fn into_raw_fd(self) -> RawFd {
        self.io.into_raw_fd()
    }
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.io.as_raw_fd()
    }
}
