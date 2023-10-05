mod params;
pub use params::BuildParams;

mod ca;
pub use ca::Ca;
mod entity;
pub use entity::EndEntity;
mod signature;

use rcgen::{Certificate, CertificateParams, RcgenError};

pub trait CertParams {
    fn params(&self) -> &CertificateParams;
}

#[derive(Debug, Clone)]
/// Struct to represent a Serialized Cert/Key pair
pub struct SerializedEntity {
    pub cert_pem: String,
    pub key_pem: String,
}

pub trait Cert {
    fn serialize(&self, signer: Option<&Certificate>) -> Result<SerializedEntity, RcgenError>;
    fn cert(&self) -> &Certificate;
}
