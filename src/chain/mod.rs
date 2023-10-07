use itertools::Itertools;
use rcgen::RcgenError;
use std::{fs::File, path::Path};

use crate::{
    cert::{Ca, Cert, EndEntity, SerializedEntity},
    BuildParams,
};
/// Chain that has been finalized by adding an end-entity. Note that
/// if we wanted a more complex application that stored chains and
/// allowed updates to them, we might want a tree structure. But for
/// fire-and-forget scenarios like this app is meant to support, we
/// just need a temporary vector.
pub struct TerminatedChain {
    chain: Vec<Box<dyn Cert>>,
}

impl TerminatedChain {
    /// Serialize chain to vec of Pems (`Vec<String>`)
    pub fn serialize(self) -> Result<Vec<SerializedEntity>, RcgenError> {
        let no_ca = self
            .chain
            .iter()
            .tuple_windows()
            .map(|(signer, signee)| signee.serialize(Some(signer.cert())));
        // n = 0 is self-signed, the rest are signed by n - 1
        self.chain
            .first()
            .iter()
            .map(|ca| ca.serialize(None))
            .chain(no_ca)
            .collect::<Result<Vec<SerializedEntity>, RcgenError>>()
    }
}

/// Struct to initialize the build of a Certificate Chain that holds
/// only a `Ca`.
pub struct CertChain(Ca);

impl CertChain {
    /// Initialize the CertChain.
    pub fn new(ca: Option<Ca>) -> Result<Self, RcgenError> {
        if let Some(ca) = ca {
            Ok(Self(ca))
        } else {
            let ca = BuildParams::new().ca().build()?;
            Ok(Self(ca))
        }
    }

    /// Add an entity to the chain. Can only be called on a non-empty chain.
    pub fn end(self, entity: Option<EndEntity>) -> crate::Result<TerminatedChain> {
        let mut chain: Vec<Box<dyn Cert>> = vec![Box::new(self.0)];
        if let Some(entity) = entity {
            chain.push(Box::new(entity));
        } else {
            let entity = BuildParams::new().end_entity().build()?;
            chain.push(Box::new(entity));
        }
        Ok(TerminatedChain { chain })
    }
    /// Write Pem files to given directory, assigning predetermined names to files.
    pub fn write_to_dir(dir: &Path, mut chain: Vec<SerializedEntity>) -> crate::Result<()> {
        use std::io::Write;

        // first serialize end-entity.
        chain.pop().iter().try_for_each(|e| {
            let cert_path = dir.join("cert.pem");
            let key_path = dir.join("cert.key.pem");
            let mut cert_out = File::create(cert_path)?;
            let mut key_out = File::create(key_path)?;
            write!(cert_out, "{}", e.cert_pem)?;
            write!(key_out, "{}", e.key_pem)?;
            Ok::<(), std::io::Error>(())
        })?;

        let intermediats = chain.split_off(1);

        // first serialize Ca
        chain.iter().try_for_each(|e| {
            let cert_path = dir.join("root-ca.pem");
            let key_path = dir.join("root-ca.key.pem");
            let mut cert_out = File::create(cert_path)?;
            let mut key_out = File::create(key_path)?;
            write!(cert_out, "{}", e.cert_pem)?;
            write!(key_out, "{}", e.key_pem)?;
            Ok::<(), std::io::Error>(())
        })?;

        intermediats.iter().enumerate().try_for_each(|(i, e)| {
            let base = format!("intermediate-{}", i);
            let cert_path = dir.join(format!("{}.pem", base));
            let key_path = dir.join(format!("{}.key.pem", base));
            let mut cert_out = File::create(cert_path)?;
            let mut key_out = File::create(key_path)?;
            write!(cert_out, "{}", e.cert_pem)?;
            write!(key_out, "{}", e.key_pem)?;
            Ok::<(), std::io::Error>(())
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use pem::{Pem, PemError};
    use x509_parser::prelude::{FromDer, X509Certificate, X509Error};

    use super::*;

    #[test]
    fn test_init_chain() -> crate::Result<()> {
        let chain = CertChain::new(None);
        assert!(chain.is_ok());
        Ok(())
    }
    #[test]
    fn test_finalize_chain() -> crate::Result<()> {
        let chain = CertChain::new(None)?.end(None);
        assert!(chain.is_ok());
        Ok(())
    }
    #[test]
    fn test_serialize_chain() -> crate::Result<()> {
        let chain = CertChain::new(None)?.end(None)?.serialize();
        assert!(chain.is_ok());

        let chain = chain?;
        assert_eq!(&chain.len(), &2);
        for e in chain {
            assert!(e.cert_pem.contains("BEGIN CERTIFICATE"));
            assert!(e.key_pem.contains("BEGIN PRIVATE KEY"));
        }
        Ok(())
    }

    #[test]
    fn test_chain_verifies() -> crate::Result<()> {
        let chain = CertChain::new(None)?.end(None)?.serialize();
        assert!(chain.is_ok());

        let ders: Vec<Pem> = chain?
            .iter()
            .map(|s| pem::parse(&s.cert_pem))
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
            .map(|(issuer, cert)| check_signature(cert, issuer))
            .collect();

        for n in verified {
            assert!(n);
        }
        Ok(())
    }

    #[test]
    fn test_chain_write_files() -> crate::Result<()> {
        use assert_fs::prelude::*;
        let temp = assert_fs::TempDir::new()?;
        let dir = temp.path();
        let ca_cert = temp.child("root-ca.pem");
        let ca_key = temp.child("root-ca.key.pem");
        let entity_cert = temp.child("cert.pem");
        let entity_key = temp.child("cert.key.pem");

        let chain = CertChain::new(None)?.end(None)?.serialize()?;

        CertChain::write_to_dir(dir, chain.clone())?;
        // assert file creation contents
        let ca_entity = chain.get(0).unwrap();
        let end_entity = chain.get(1).unwrap();
        ca_cert.assert(ca_entity.cert_pem.as_str());
        ca_key.assert(ca_entity.key_pem.clone().as_str());
        entity_key.assert(end_entity.key_pem.clone().as_str());
        entity_cert.assert(end_entity.cert_pem.as_str());

        Ok(())
    }

    pub fn check_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
        let issuer_public_key = issuer.public_key();
        cert.verify_signature(Some(issuer_public_key)).is_ok()
    }
}
