extern crate rustls;
extern crate hyper;
#[cfg(feature = "client")] extern crate webpki_roots;

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
}

impl TlsStream {
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
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.sess.read(buf)? {
                // If there's no plaintext, either we need to keep reading or
                // writing TLS-specific things or there's really nothing left.
                0 => {
                    if self.sess.wants_write() {
                        self.sess.write_tls(&mut self.underlying)?;
                    } else if self.sess.wants_read() {
                        if self.sess.read_tls(&mut self.underlying)? == 0 {
                            return Ok(0); // there is no data left to read.
                        } else {
                            self.sess.process_new_packets()
                                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e))?;
                        }
                    } else {
                        return Ok(0);
                    }
                }
                n => return Ok(n)
            }
        }
    }
}

impl io::Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self.sess.write(buf)?;
        self.sess.write_tls(&mut self.underlying)?;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        let rc = self.sess.flush();
        self.sess.write_tls(&mut self.underlying)?;
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

        TlsServer { cfg: Arc::new(tls_config) }
    }

    pub fn with_config(config: rustls::ServerConfig) -> TlsServer {
        TlsServer { cfg: Arc::new(config) }
    }
}

#[cfg(feature = "server")]
impl SslServer for TlsServer {
    type Stream = WrappedStream;

    fn wrap_server(&self, stream: HttpStream) -> hyper::Result<WrappedStream> {
        let tls = TlsStream {
            sess: Box::new(rustls::ServerSession::new(&self.cfg)),
            underlying: stream,
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

    pub type Result<T> = ::std::result::Result<T, Error>;

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

    pub fn load_certs(filename: &str) -> Result<Vec<rustls::Certificate>> {
        let certfile = fs::File::open(filename).map_err(|e| Error::Io(e))?;
        let mut reader = BufReader::new(certfile);
        pemfile::certs(&mut reader).map_err(|_| Error::BadCerts)
    }

    pub fn load_private_key(filename: &str) -> Result<rustls::PrivateKey> {
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
