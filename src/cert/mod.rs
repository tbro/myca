use rand::rngs::OsRng;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyUsagePurpose, RcgenError,
};
use rsa::pkcs8::EncodePrivateKey;

use rsa::RsaPrivateKey;

pub struct BuildCert {
    params: CertificateParams,
}

impl Default for BuildCert {
    fn default() -> Self {
        Self::new()
    }
}

impl BuildCert {
    pub fn new() -> Self {
        let mut params = CertificateParams::default();
        // for now defaulting to RSA but we can make configurable later
        params.alg = &rcgen::PKCS_RSA_SHA256;
        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
        let private_key_der = private_key.to_pkcs8_der().unwrap();
        let key_pair = rcgen::KeyPair::try_from(private_key_der.as_bytes()).unwrap();
        params.key_pair = Some(key_pair);
        Self { params }
    }
    /// Set options for generating a CA cert. Since in this simplified setup
    /// CA = ROOT, CA certs are self-signed. So we generate the keys here.
    pub fn ca(mut self) -> Self {
        self.params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        self.params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        self.params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        self.params.key_usages.push(KeyUsagePurpose::CrlSign);
        self
    }
    pub fn end_entity(mut self, client_auth: bool) -> Self {
        self.params.is_ca = IsCa::NoCa;
        let name = "viewd.host.home";
        self.params
            .subject_alt_names
            .push(rcgen::SanType::DnsName(name.to_string()));
        self.params
            .distinguished_name
            .push(DnType::CommonName, name);
	if client_auth {
	    self.client_auth()
	} else {
	    self.server_auth()
	}
    }
    pub fn client_auth(mut self) -> Self {
        let usage = ExtendedKeyUsagePurpose::ClientAuth;
        self.params.extended_key_usages.push(usage);
        self
    }
    pub fn server_auth(mut self) -> Self {
        let usage = ExtendedKeyUsagePurpose::ServerAuth;
        self.params.extended_key_usages.push(usage);
        self
    }
    pub fn build(self) -> Result<Certificate, RcgenError> {
        Certificate::from_params(self.params)
    }
    /// Sign with given ca and serialize
    pub fn serialize_with_signer(self, ca: &Certificate) -> Result<String, RcgenError> {
        let entity = Certificate::from_params(self.params)?;
        entity.serialize_pem_with_signer(ca)
    }
}

#[cfg(test)]
mod tests {
    use x509_parser::{
        nom::AsBytes,
        prelude::{FromDer, X509Certificate},
    };

    use super::*;

    #[test]
    fn test_cert_chain() -> Result<(), RcgenError> {
        let ca = BuildCert::new().ca().build()?;
        let entity = BuildCert::new().end_entity();
        let entity_pem = entity.serialize_with_signer(&ca)?;
        let entity_parsed = pem::parse(&entity_pem)?;
        let der_serialized = entity_parsed.contents();
        let ca_der = ca.serialize_der()?;
        let (_, cert) = X509Certificate::from_der(der_serialized).unwrap();
        let (_, ca) = X509Certificate::from_der(ca_der.as_bytes()).unwrap();
        let verified = check_signature(&cert, &ca);
        assert!(verified);

        Ok(())
    }
    #[test]
    fn init_ca() {
        let cert = BuildCert::new().ca();
        assert_eq!(cert.params.is_ca, IsCa::Ca(BasicConstraints::Unconstrained))
    }
    #[test]
    fn init_end_entity() {
        let cert = BuildCert::new().end_entity().client_auth();
        assert_eq!(cert.params.is_ca, IsCa::NoCa);
        assert_eq!(
            cert.params.extended_key_usages,
            vec![ExtendedKeyUsagePurpose::ClientAuth]
        );
    }

    // pub fn check_signature(cert: &Certificate, issuer: &Certificate) -> bool {
    pub fn check_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
        let issuer_public_key = issuer.public_key();

        cert.verify_signature(Some(issuer_public_key)).is_ok()
    }
}
