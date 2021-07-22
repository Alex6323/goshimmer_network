use std::io;

#[derive(Debug)]
pub enum NetworkError {
    BindingToAddr,
    SocketRead(io::Error),
}
