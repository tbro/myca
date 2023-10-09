use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyUsagePurpose};

use super::ca::CaParams;
use super::entity::EndEntityParams;
use super::signature::Signature;

/// Builder to configure TLS [CertificateParams] to be finalized
/// into either a Ca or an End-Entity.
pub struct BuildParams {
    params: CertificateParams,
}

impl Default for BuildParams {
    fn default() -> Self {
        Self::new()
    }
}

impl BuildParams {
    /// Initialize `CertificateParams` with defaults
    /// # Example
    /// ```
    /// # use myca::BuildParams;
    /// let cert = BuildParams::new();
    /// ```
    pub fn new() -> Self {
        let params = CertificateParams::default();
        Self { params }
    }
    /// Set signature algorithm (instead of default). Returns `crate::Result<Self>`.
    /// # Example
    /// ```
    /// # use myca::BuildParams;
    /// let cert = BuildParams::new().with_alg("pkcs_ed25519");
    /// ```
    pub fn with_alg(mut self, alg: &str) -> crate::Result<Self> {
        let sig = Signature::new(alg)?;
        self.params.alg = sig.key_pair.algorithm();
        self.params.key_pair = Some(sig.key_pair);
        Ok(self)
    }
    /// Set options for generating a CA cert. In this setup
    /// CA = ROOT (CA certs are self-signed).
    /// # Example
    /// ```
    /// # use myca::BuildParams;
    /// let cert = BuildParams::new().ca();
    /// ```
    pub fn ca(mut self) -> CaParams {
        self.params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        self.params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        self.params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        self.params.key_usages.push(KeyUsagePurpose::CrlSign);
        CaParams::new(self.params)
    }
    /// Set options for `EndEntity` Certificates
    pub fn end_entity(mut self) -> EndEntityParams {
        self.params.is_ca = IsCa::NoCa;
        EndEntityParams::new(self.params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{Cert, CertParams};
    use x509_parser::prelude::{FromDer, X509Certificate};

    #[test]
    fn init_ca() {
        let cert = BuildParams::new().ca();
        assert_eq!(
            cert.params().is_ca,
            IsCa::Ca(BasicConstraints::Unconstrained)
        )
    }
    #[test]
    fn with_sig_algo_default() -> crate::Result<()> {
        let end_entity = BuildParams::new().end_entity();

        assert_eq!(end_entity.params().alg, &rcgen::PKCS_ECDSA_P256_SHA256);
        Ok(())
    }
    #[test]
    fn with_sig_algo_rsa_sha256() -> crate::Result<()> {
        let end_entity = BuildParams::new().with_alg("PKCS_RSA_SHA256")?.end_entity();

        assert_eq!(end_entity.params().alg, &rcgen::PKCS_RSA_SHA256);
        Ok(())
    }
    #[test]
    fn serialize_end_entity_default_sig() -> crate::Result<()> {
        let ca = BuildParams::new().ca().build()?;
        let end_entity = BuildParams::new()
            .end_entity()
            .build()?
            .serialize(Some(ca.cert()))?;

        let der = pem::parse(end_entity.cert_pem)?;
        let (_, cert) = X509Certificate::from_der(der.contents())?;

        let issuer_der = pem::parse(ca.serialize(None)?.cert_pem)?;
        let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

        let verified = check_signature(&cert, &issuer);
        assert!(verified);
        Ok(())
    }
    #[test]
    fn serialize_end_entity_ecdsa_p384_sha384_sig() -> crate::Result<()> {
        let ca = BuildParams::new().ca().build()?;
        let end_entity = BuildParams::new()
            .with_alg("PKCS_ECDSA_P384_SHA384")?
            .end_entity()
            .build()?
            .serialize(Some(ca.cert()))?;

        let der = pem::parse(end_entity.cert_pem)?;
        let (_, cert) = X509Certificate::from_der(der.contents())?;

        let issuer_der = pem::parse(ca.serialize(None)?.cert_pem)?;
        let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

        let verified = check_signature(&cert, &issuer);
        assert!(verified);
        Ok(())
    }

    #[test]
    fn serialize_end_entity_ed25519_sig() -> crate::Result<()> {
        let ca = BuildParams::new().ca().build()?;
        let end_entity = BuildParams::new()
            .with_alg("PKCS_ED25519")?
            .end_entity()
            .build()?
            .serialize(Some(ca.cert()))?;

        let der = pem::parse(end_entity.cert_pem)?;
        let (_, cert) = X509Certificate::from_der(der.contents())?;

        let issuer_der = pem::parse(ca.serialize(None)?.cert_pem)?;
        let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

        let verified = check_signature(&cert, &issuer);
        assert!(verified);
        Ok(())
    }
    #[test]
    fn serialize_end_entity_rsa_256_sig() -> crate::Result<()> {
        let ca = BuildParams::new().ca().build()?;
        let end_entity = BuildParams::new()
            .with_alg("PKCS_RSA_SHA256")?
            .end_entity()
            .build()?
            .serialize(Some(ca.cert()))?;

        let der = pem::parse(end_entity.cert_pem)?;
        let (_, cert) = X509Certificate::from_der(der.contents())?;

        let issuer_der = pem::parse(ca.serialize(None)?.cert_pem)?;
        let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

        let verified = check_signature(&cert, &issuer);
        assert!(verified);
        Ok(())
    }
    #[test]
    fn serialize_end_entity_rsa_384_sig() -> crate::Result<()> {
        let ca = BuildParams::new().ca().build()?;
        let end_entity = BuildParams::new()
            .with_alg("PKCS_RSA_SHA384")?
            .end_entity()
            .build()?
            .serialize(Some(ca.cert()))?;

        let der = pem::parse(end_entity.cert_pem)?;
        let (_, cert) = X509Certificate::from_der(der.contents())?;

        let issuer_der = pem::parse(ca.serialize(None)?.cert_pem)?;
        let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

        let verified = check_signature(&cert, &issuer);
        assert!(verified);
        Ok(())
    }
    #[test]
    fn serialize_end_entity_rsa_512_sig() -> crate::Result<()> {
        let ca = BuildParams::new().ca().build()?;
        let end_entity = BuildParams::new()
            .with_alg("PKCS_RSA_SHA512")?
            .end_entity()
            .build()?
            .serialize(Some(ca.cert()))?;

        let der = pem::parse(end_entity.cert_pem)?;
        let (_, cert) = X509Certificate::from_der(der.contents())?;

        let issuer_der = pem::parse(ca.serialize(None)?.cert_pem)?;
        let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

        let verified = check_signature(&cert, &issuer);
        assert!(verified);
        Ok(())
    }
    pub fn check_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
        let issuer_public_key = issuer.public_key();
        cert.verify_signature(Some(issuer_public_key)).is_ok()
    }
}
