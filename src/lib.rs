extern crate rustls;
extern crate hyper;
#[cfg(feature = "client")]
extern crate webpki_roots;

use std::io;
use std::sync::Arc;
use std::sync::{Mutex, MutexGuard};
use std::net::{SocketAddr, Shutdown};
use std::time::Duration;

use hyper::net::{HttpStream, NetworkStream};
#[cfg(feature = "client")] use hyper::net::SslClient;
#[cfg(feature = "server")] use hyper::net::SslServer;

pub struct TlsStream {
    sess: Box<rustls::Session>,
    underlying: HttpStream,
    eof: bool,
    tls_error: Option<rustls::TLSError>,
    io_error: Option<io::Error>
}

impl TlsStream {
    fn underlying_read(&mut self) {
        if self.io_error.is_some() || self.tls_error.is_some() {
            return;
        }

        if self.sess.wants_read() {
            match self.sess.read_tls(&mut self.underlying) {
                Err(err) => {
                    if err.kind() != io::ErrorKind::WouldBlock {
                        self.io_error = Some(err);
                    }
                },
                Ok(0) => {
                    self.eof = true;
                },
                Ok(_) => ()
            }
        }

        if let Err(err) = self.sess.process_new_packets() {
            self.tls_error = Some(err);
        }
    }

    fn underlying_write(&mut self) {
        if self.io_error.is_some() || self.tls_error.is_some() {
            return;
        }

        while self.io_error.is_none() && self.sess.wants_write() {
            if let Err(err) = self.sess.write_tls(&mut self.underlying) {
                if err.kind() != io::ErrorKind::WouldBlock {
                    self.io_error = Some(err);
                }
            }
        }
    }

    #[inline]
    fn underlying_io(&mut self) {
        self.underlying_write();
        self.underlying_read();
    }

    #[inline]
    fn promote_tls_error(&mut self) -> io::Result<()> {
        self.tls_error.take()
            .map(|err| Err(io::Error::new(io::ErrorKind::ConnectionAborted, err)))
            .unwrap_or(Ok(()))
    }

    #[inline]
    fn check_io_error(&mut self) -> io::Result<()> {
        self.io_error.take().map(Err).unwrap_or(Ok(()))
    }

    #[inline]
    fn close(&mut self, how: Shutdown) -> io::Result<()> {
        self.underlying.close(how)
    }

    #[inline(always)]
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.underlying.peer_addr()
    }

    #[inline(always)]
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.underlying.set_read_timeout(dur)
    }

    #[inline(always)]
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.underlying.set_write_timeout(dur)
    }
}

impl io::Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // This wants to block if we don't have any data ready.
        // underlying_read does this.
        loop {
            self.promote_tls_error()?;
            self.check_io_error()?;

            if self.eof {
                return Ok(0);
            }

            match self.sess.read(buf) {
                Ok(0) => self.underlying_io(),
                Ok(n) => return Ok(n),
                Err(e) => return Err(e)
            }
        }
    }
}

impl io::Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self.sess.write(buf)?;
        self.promote_tls_error()?;
        self.underlying_write();
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        let rc = self.sess.flush();
        self.promote_tls_error()?;
        self.underlying_write();
        rc
    }
}

#[derive(Clone)]
pub struct WrappedStream(Arc<Mutex<TlsStream>>);

impl WrappedStream {
    #[inline]
    fn lock(&self) -> MutexGuard<TlsStream> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl io::Read for WrappedStream {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.lock().read(buf)
    }
}

impl io::Write for WrappedStream {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.lock().write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.lock().flush()
    }
}

impl NetworkStream for WrappedStream {
    #[inline]
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.lock().peer_addr()
    }

    #[inline]
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.lock().set_read_timeout(dur)
    }

    #[inline]
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.lock().set_write_timeout(dur)
    }

    #[inline]
    fn close(&mut self, how: Shutdown) -> io::Result<()> {
        self.lock().close(how)
    }
}

#[cfg(feature = "client")]
pub struct TlsClient {
    pub cfg: Arc<rustls::ClientConfig>
}

#[cfg(feature = "client")]
impl TlsClient {
    pub fn new() -> TlsClient {
        let mut tls_config = rustls::ClientConfig::new();
        let cache = rustls::ClientSessionMemoryCache::new(64);
        tls_config.set_persistence(cache);
        tls_config.root_store.add_trust_anchors(&webpki_roots::ROOTS);

        TlsClient {
            cfg: Arc::new(tls_config)
        }
    }
}

#[cfg(feature = "client")]
impl SslClient for TlsClient {
    type Stream = WrappedStream;

    fn wrap_client(&self, stream: HttpStream, host: &str) -> hyper::Result<WrappedStream> {
        let tls = TlsStream {
            sess: Box::new(rustls::ClientSession::new(&self.cfg, host)),
            underlying: stream,
            eof: false,
            io_error: None,
            tls_error: None
        };

        Ok(WrappedStream(Arc::new(Mutex::new(tls))))
    }
}

#[cfg(feature = "server")]
#[derive(Clone)]
pub struct TlsServer {
    pub cfg: Arc<rustls::ServerConfig>
}

#[cfg(feature = "server")]
impl TlsServer {
    pub fn new(certs: Vec<rustls::Certificate>, key: rustls::PrivateKey) -> TlsServer {
        let mut tls_config = rustls::ServerConfig::new();
        let cache = rustls::ServerSessionMemoryCache::new(1024);
        tls_config.set_persistence(cache);
        tls_config.ticketer = rustls::Ticketer::new();
        tls_config.set_single_cert(certs, key);

        TlsServer {
            cfg: Arc::new(tls_config)
        }
    }
}

#[cfg(feature = "server")]
impl SslServer for TlsServer {
    type Stream = WrappedStream;

    fn wrap_server(&self, stream: HttpStream) -> hyper::Result<WrappedStream> {
        let tls = TlsStream {
            sess: Box::new(rustls::ServerSession::new(&self.cfg)),
            underlying: stream,
            eof: false,
            io_error: None,
            tls_error: None
        };

        Ok(WrappedStream(Arc::new(Mutex::new(tls))))
    }
}

pub mod util {
    use std::fs;
    use std::io::{self, BufReader};
    use std::error;
    use std::fmt;

    use rustls;
    use rustls::internal::pemfile;

    #[derive(Debug)]
    pub enum Error {
        Io(io::Error),
        BadCerts,
        BadKeyCount,
        BadKey,
    }

    impl error::Error for Error {
        fn description(&self) -> &str {
            match *self {
                Error::Io(ref e) => e.description(),
                Error::BadCerts => "the contents of the certificates file were invalid",
                Error::BadKeyCount => "the private key file contained more than one key",
                Error::BadKey => "the contents of the private key file were invalid",
            }
        }
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match *self {
                Error::Io(ref e) => write!(f, "I/O Error: {}", e),
                Error::BadCerts => write!(f, "invalid certificates file contents"),
                Error::BadKeyCount => write!(f, "more than one key in private key file"),
                Error::BadKey => write!(f, "invalid private key file contents"),
            }
        }
    }

    pub fn load_certs(filename: &str) -> Result<Vec<rustls::Certificate>, Error> {
        let certfile = fs::File::open(filename).map_err(|e| Error::Io(e))?;
        let mut reader = BufReader::new(certfile);
        pemfile::certs(&mut reader).map_err(|_| Error::BadCerts)
    }

    pub fn load_private_key(filename: &str) -> Result<rustls::PrivateKey, Error> {
        let keyfile = fs::File::open(filename).map_err(|e| Error::Io(e))?;
        let mut reader = BufReader::new(keyfile);
        let mut keys = pemfile::rsa_private_keys(&mut reader).map_err(|_| Error::BadKey)?;
        if keys.len() != 1 {
            Err(Error::BadKeyCount)
        } else {
            Ok(keys.remove(0))
        }
    }
}
