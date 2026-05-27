use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("auth error: {0}")]
    Auth(String),

    #[error("tunnel error: {0}")]
    Tunnel(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;
