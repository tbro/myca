use rcgen::{Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, RcgenError};

use super::{Cert, CertParams, SerializedEntity};

pub struct EndEntity {
    cert: Certificate,
    // signer: &'a Certificate,
}

impl Cert for EndEntity {
    /// Sign with `self.signer` and serialize.
    fn serialize(&self, signer: Option<&Certificate>) -> Result<SerializedEntity, RcgenError> {
        let cert_pem = self.cert.serialize_pem_with_signer(signer.unwrap())?;
        let key_pem = self.cert.serialize_private_key_pem();
        Ok(SerializedEntity { cert_pem, key_pem })
    }
    fn cert(&self) -> &Certificate {
        &self.cert
    }
}

impl CertParams for EndEntityParams {
    fn params(&self) -> &CertificateParams {
        &self.params
    }
}

/// `CertificateParams` from which an `EndEntity` `Certificate` can be built
pub struct EndEntityParams {
    params: CertificateParams,
}

impl EndEntityParams {
    /// Initialize `EndEntityParams`
    pub fn new(params: CertificateParams) -> Self {
        Self { params }
    }
    /// `DnsName` that will be recorded as both `CommonName` and
    /// `subject_alt_names`
    pub fn dns_name(mut self, name: &str) -> Self {
        self.params
            .subject_alt_names
            .push(rcgen::SanType::DnsName(name.into()));
        self.params
            .distinguished_name
            .push(DnType::CommonName, name);
        self
    }
    /// Add ClientAuth to `extended_key_usages`.
    pub fn client_auth(mut self) -> Self {
        let usage = ExtendedKeyUsagePurpose::ClientAuth;
        self.params.extended_key_usages.push(usage);
        self
    }
    /// Add ServerAuth to `extended_key_usages`.
    pub fn server_auth(mut self) -> Self {
        let usage = ExtendedKeyUsagePurpose::ServerAuth;
        self.params.extended_key_usages.push(usage);
        self
    }
    pub fn build(self) -> Result<EndEntity, RcgenError> {
        let cert = Certificate::from_params(self.params)?;
        let cert = EndEntity { cert };
        Ok(cert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cert::CertParams, BuildParams};
    use rcgen::{DnValue, ExtendedKeyUsagePurpose, IsCa};

    #[test]
    fn client_auth_end_entity() {
        let _ca = BuildParams::new().ca().build().unwrap();
        let params = CertificateParams::default();
        let cert = EndEntityParams::new(params).client_auth();
        assert_eq!(cert.params().is_ca, IsCa::NoCa);
        assert_eq!(
            cert.params().extended_key_usages,
            vec![ExtendedKeyUsagePurpose::ClientAuth]
        );
    }
    #[test]
    fn server_auth_end_entity() {
        let _ca = BuildParams::new().ca().build().unwrap();
        let params = CertificateParams::default();
        let cert = EndEntityParams::new(params).server_auth();
        assert_eq!(cert.params().is_ca, IsCa::NoCa);
        assert_eq!(
            cert.params().extended_key_usages,
            vec![ExtendedKeyUsagePurpose::ServerAuth]
        );
    }
    #[test]
    fn dns_name_end_entity() {
        let _ca = BuildParams::new().ca().build().unwrap();
        let name = "unexpected.oomyoo.xyz";
        let params = CertificateParams::default();
        let cert = EndEntityParams::new(params).dns_name(name);
        assert_eq!(
            cert.params().subject_alt_names,
            vec![rcgen::SanType::DnsName(name.into())]
        );
        assert_eq!(
            cert.params()
                .distinguished_name
                .get(&DnType::CommonName)
                .unwrap(),
            &DnValue::from(name)
        );
    }
}
