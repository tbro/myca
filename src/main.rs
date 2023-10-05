use std::{
    fs,
    path::{Path, PathBuf},
};

use argh::FromArgs;
use myca::{BuildParams, Cert, CertChain};
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(FromArgs, PartialEq, Debug)]
/// Generate a TLS Certificate Chain
pub struct Cli {
    #[argh(option, short = 'o', default = "Path::new(\"tls\").to_path_buf()")]
    /// output directory for Pem files (defaults to `./tls`)
    pub output: PathBuf,
    #[argh(option, short = 'l', default = "default_chain_len()")]
    /// chain length (defaults to 2)
    pub length: usize,
    #[argh(switch, short = 'c')]
    /// switch `ExtendedKeyUsage` to clientAuth (instead of the default: serverAuth)
    pub clientauth: bool,
    #[argh(option, short = 'd', default = "String::from(\"my.host.home\")")]
    /// fqdn of end-entity (will be used in certificate validation)
    pub dnsname: String,
    #[argh(
        option,
        short = 's',
        default = "String::from(\"pkcs_ecdsa_p256_sha256\")"
    )]
    /// signature algorithm (default: "pkcs_ecdsa_p256_sha256"),
    /// options: ["pkcs_ecdsa_p256_sha256", "pkcs_rsa_sha256", "pkcs_ed25519"]
    pub sig_algo: String,
    #[argh(option, short = 'p')]
    /// print contents of certificate instead of creating new ones
    pub parse: Option<PathBuf>,
}

fn main() -> myca::Result<()> {
    let cli: Cli = argh::from_env();
    if let Some(path) = cli.parse {
        let s = fs::read_to_string(path)?;
        let parsed = pem::parse(s)?;
        let (_, cert) = X509Certificate::from_der(parsed.contents()).unwrap();
        println!("{:#?}", cert);
    } else {
        let ca = BuildParams::new().with_alg(&cli.sig_algo)?.ca().build()?;
        let chain = CertChain::new(Some(ca))?;
        let mut entity = BuildParams::new()
            .with_alg(&cli.sig_algo)?
            .end_entity()
            .dns_name(&cli.dnsname);
        if cli.clientauth {
            entity = entity.client_auth();
        } else {
            entity = entity.server_auth();
        }
        let s = chain.end(entity.build().ok())?.serialize()?;
        CertChain::write_to_dir(&cli.output, s.clone())?;
    }

    Ok(())
}

fn default_chain_len() -> usize {
    2
}
