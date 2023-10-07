use std::fmt::Display;

#[derive(Debug)]
pub enum KeyGenerationError {
    Unspecified(ring::error::Unspecified),
    UnsupportedAlgorithm,
    RcgenError(rcgen::RcgenError),
    Pkcs8Error(rsa::pkcs8::Error),
    RsaError(rsa::Error),
}

impl Display for KeyGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyGenerationError::Unspecified(u) => write!(f, "{}", u),
            KeyGenerationError::UnsupportedAlgorithm => write!(f, ""),
            KeyGenerationError::RcgenError(e) => write!(f, "{}", e),
            KeyGenerationError::Pkcs8Error(e) => write!(f, "{}", e),
            KeyGenerationError::RsaError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for KeyGenerationError {}

impl From<rcgen::RcgenError> for KeyGenerationError {
    fn from(err: rcgen::RcgenError) -> Self {
        KeyGenerationError::RcgenError(err)
    }
}
impl From<ring::error::Unspecified> for KeyGenerationError {
    fn from(err: ring::error::Unspecified) -> Self {
        KeyGenerationError::Unspecified(err)
    }
}
impl From<rsa::pkcs8::Error> for KeyGenerationError {
    fn from(err: rsa::pkcs8::Error) -> Self {
        KeyGenerationError::Pkcs8Error(err)
    }
}
impl From<rsa::Error> for KeyGenerationError {
    fn from(err: rsa::Error) -> Self {
        KeyGenerationError::RsaError(err)
    }
}
pub struct Signature<'a> {
    pub alg: &'a rcgen::SignatureAlgorithm,
    pub key_pair: rcgen::KeyPair,
}

impl Signature<'_> {
    pub fn new(s: &str) -> Result<Self, KeyGenerationError> {
        match s.to_lowercase().as_str() {
            "pkcs_rsa_sha256" => Self::pkcs_rsa_sha256(),
            //     "PKCS_RSA_SHA384"
            // 	"PKCS_RSA_SHA512"
            // 	"PKCS_RSA_PSS_SHA256"
            "pkcs_ecdsa_p256_sha256" => Self::pkcs_ecdsa_p256_sha256(),
            // 	"PKCS_ECDSA_P384_SHA384"
            "pkcs_ed25519" => Self::pkcs_ed25519(),
            &_ => Err(KeyGenerationError::UnsupportedAlgorithm),
        }
    }
    pub fn pkcs_ed25519() -> Result<Self, KeyGenerationError> {
        use ring::signature::Ed25519KeyPair;

        let rng = ring::rand::SystemRandom::new();
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        #[rustfmt::skip]
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)?;

        let key_pair = rcgen::KeyPair::try_from(pkcs8_bytes.as_ref())?;

        Ok(Self { alg, key_pair })
    }

    pub fn pkcs_rsa_sha256() -> Result<Self, KeyGenerationError> {
        use rand::rngs::OsRng;
        use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};

        let alg = &rcgen::PKCS_RSA_SHA256;
        // TODO review if ring::rand::SystemRandom should/can be used here
        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits)?;
        let private_key_der = private_key.to_pkcs8_der()?;
        let key_pair = rcgen::KeyPair::try_from(private_key_der.as_bytes())?;

        Ok(Self { alg, key_pair })
    }
    pub fn pkcs_ecdsa_p256_sha256() -> Result<Self, KeyGenerationError> {
        use ring::signature::EcdsaKeyPair;
        use ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;

        let rng = ring::rand::SystemRandom::new();
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        #[rustfmt::skip]
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)?;

        let key_pair = rcgen::KeyPair::try_from(pkcs8_bytes.as_ref())?;

        Ok(Self { alg, key_pair })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_pkcs_ed25519() -> crate::Result<()> {
        let sig = Signature::new("pkcs_ed25519")?;
        assert_eq!(format!("{:?}", sig.alg), "PKCS_ECDSA_P256_SHA256");
        assert_eq!(format!("{:?}", sig.key_pair.algorithm()), "PKCS_ED25519");
        Ok(())
    }

    #[test]
    fn signature_pkcs_ecdsa_p256_sha256() -> crate::Result<()> {
        let sig = Signature::new("PKCS_ECDSA_P256_SHA256")?;
        assert_eq!(format!("{:?}", sig.alg), "PKCS_ECDSA_P256_SHA256");
        assert_eq!(
            format!("{:?}", sig.key_pair.algorithm()),
            "PKCS_ECDSA_P256_SHA256"
        );
        Ok(())
    }

    #[test]
    fn signature_pkcs_rsa_sha256() -> crate::Result<()> {
        let sig = Signature::new("PKCS_RSA_SHA256")?;
        assert_eq!(format!("{:?}", sig.alg), "PKCS_RSA_SHA256");
        assert_eq!(format!("{:?}", sig.key_pair.algorithm()), "PKCS_RSA_SHA256");
        Ok(())
    }
}
