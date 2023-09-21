use thiserror::Error;

#[derive(Error, Debug)]
pub enum InterfaceError {
    #[error("Failed to list interfaces: `{0}`")]
    FailedToListInterfaces(String),
}
