use itertools::Itertools;
use rcgen::Certificate;
use std::fs::File;
use std::path::Path;

#[derive(Debug, Clone)]
/// Struct to represent a Serialized Cert/Key pair
pub struct SerializedEntity {
    cert_pem: String,
    key_pem: Option<String>,
}

#[derive(Default)]
/// Struct to represent a Certificate Chain as a Vec of Certificates.
pub struct CertChain {
    chain: Vec<Certificate>,
}

impl CertChain {
    /// Initialize the CertChain
    pub fn new() -> Self {
        Self {
            chain: Vec::new(),
        }
    }
    /// Add a CA to the chain. Can only be called on empty chain.
    pub fn ca(&mut self, ca: Certificate) -> crate::Result<&Self> {
        if !self.chain.is_empty() {
            return Err("CA already exists".into());
        } else {
            self.chain.push(ca);
        };
        Ok(self)
    }
    /// Add an entity to the chain. Can only be called on a non-empty chain.
    pub fn end_entity(&mut self, end_entity: Certificate) -> crate::Result<&Self> {
        if self.chain.is_empty() {
            return Err("Cannot push end entity to empty chain".into());
        } else {
            self.chain.push(end_entity);
        };
        Ok(self)
    }
    /// Serialize chain to vec of Pems (`Vec<String>`)
    pub fn serialize_items(self) -> crate::Result<Vec<SerializedEntity>> {
        let mut v: Vec<SerializedEntity> = Vec::new();
        for (i, (signer, signee)) in self.chain.iter().tuple_windows().enumerate() {
            let signee_pem = signee.serialize_pem_with_signer(signer)?;
            let key_pem = signee.serialize_private_key_pem();
            let signer_pem = signer.serialize_pem()?;
            // this is meant to support chains longer than 2, but untested
            if i == 0 {
                v.push(SerializedEntity {
                    cert_pem: signer_pem,
                    key_pem: None,
                });
            }
            v.push(SerializedEntity {
                cert_pem: signee_pem,
                key_pem: Some(key_pem),
            });
        }
        Ok(v)
    }
    /// Write Pem files to given directory, assigning predetermined names to files.
    pub fn write_to_dir(dir: &Path, chain: Vec<SerializedEntity>) -> crate::Result<()> {
        use std::io::Write;
        let path = dir.clone();
        let key_path = dir.clone();
        for (i, entity) in chain.iter().enumerate() {
            let cert_path = if i == 0 {
                path.join("root-ca.pem")
            } else if i == chain.len() - 1 {
                path.join("cert.pem")
            } else {
                path.join("intermediary-{}.pem")
            };
            let mut output = File::create(cert_path)?;
            write!(output, "{}", entity.cert_pem)?;
            if let Some(key) = entity.key_pem.clone() {
                let path = key_path.join("signing.key.pem");
                let mut output = File::create(path)?;
                write!(output, "{}", key)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use pem::{Pem, PemError};
    use x509_parser::prelude::{FromDer, X509Certificate, X509Error};

    use super::*;
    use crate::cert::BuildCert;

    #[test]
    fn test_chain_from_ca_and_entity() -> crate::Result<()> {
        let mut chain = CertChain::default();
        let ca = BuildCert::new().ca().build()?;
        chain.ca(ca)?;
        let entity = BuildCert::new().end_entity().build()?;
        chain.end_entity(entity)?;
        let s = chain.serialize_items()?;

        let ders: Vec<Pem> = s
            .iter()
            .map(|entity| pem::parse(entity.cert_pem.clone()))
            .collect::<Result<Vec<Pem>, PemError>>()?;

        let x509s: Vec<_> = ders
            .iter()
            .map(|pem| {
                let (_, cert) = X509Certificate::from_der(pem.contents())?;
                Ok(cert)
            })
            .collect::<Result<Vec<X509Certificate>, X509Error>>()?;

        let verified: Vec<bool> = x509s
            .iter()
            .tuple_windows()
            .map(|(issuer, cert)| check_signature(&cert, &issuer))
            .collect();
        assert!(verified[0]);
        Ok(())
    }

    #[test]
    fn test_chain_write_files() -> crate::Result<()> {
        use assert_fs::prelude::*;
        let temp = assert_fs::TempDir::new()?;
        let path = temp.path();
        let ca_file = temp.child("root-ca.pem");
        let cert_file = temp.child("cert.pem");
        let key_file = temp.child("signing.key.pem");

        let mut chain = CertChain::default();
        let ca = BuildCert::new().ca().build()?;
        chain.ca(ca)?;
        let entity = BuildCert::new().end_entity().build()?;
        chain.end_entity(entity)?;
        let s = chain.serialize_items()?;

        CertChain::write_to_dir(path, s.clone())?;
        // assert file creation contents
        let ca_entity = s.get(0).unwrap();
        let end_entity = s.get(1).unwrap();
        ca_file.assert(ca_entity.cert_pem.as_str());
        key_file.assert(end_entity.key_pem.clone().unwrap().as_str());
        cert_file.assert(end_entity.cert_pem.as_str());

        Ok(())
    }

    pub fn check_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
        let issuer_public_key = issuer.public_key();

        cert.verify_signature(Some(issuer_public_key)).is_ok()
    }
}
