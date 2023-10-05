use rcgen::{Certificate, CertificateParams, RcgenError};

use super::{Cert, CertParams, SerializedEntity};

pub struct CaParams {
    params: CertificateParams,
}

impl CertParams for CaParams {
    fn params(&self) -> &CertificateParams {
        &self.params
    }
}

impl CaParams {
    pub fn new(params: CertificateParams) -> Self {
        Self { params }
    }
    pub fn build(self) -> Result<Ca, RcgenError> {
        let cert = Certificate::from_params(self.params)?;
        let cert = Ca { cert };
        Ok(cert)
    }
}

pub struct Ca {
    cert: Certificate,
}

impl Ca {
    pub fn cert(&self) -> &Certificate {
        &self.cert
    }
}

impl Cert for Ca {
    /// Self-sign and serialize
    fn serialize(&self, _: Option<&Certificate>) -> Result<SerializedEntity, RcgenError> {
        let cert_pem = self.cert.serialize_pem()?;
        let key_pem = self.cert.serialize_private_key_pem();
        Ok(SerializedEntity { cert_pem, key_pem })
    }
    fn cert(&self) -> &Certificate {
        &self.cert
    }
}
