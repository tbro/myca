use std::{
    fs,
    path::{Path, PathBuf},
};

use argh::FromArgs;
use myca::{BuildCert, CertChain};
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
        let mut chain = CertChain::default();
        let ca = BuildCert::new().ca().build()?;
        chain.ca(ca)?;
        let entity = BuildCert::new().end_entity(cli.clientauth).build()?;
        chain.end_entity(entity)?;
        let s = chain.serialize_items()?;
	CertChain::write_to_dir(&cli.output, s.clone())?;
    }

    Ok(())
}

fn default_chain_len() -> usize {
    2
}
