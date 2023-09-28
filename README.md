# myca

My CA is a developer tool to generate TLS certificate chains. It is
meant to be used in developers workflow, and can currently generate
certificate chain consisting of 1 Root CA and 1 end-entity certificate,
along with end-entity's private key. End-entity will be signed by
Root CA. These have been shown to function with rustls validation,
verification and encryption, but there is still much to improve so use
with caution. Many options that are currently hard-coded will be moved
to configuration / cli params in the future.

# usage
Having compiled the binary you can simply pass a path to output
generated files.

	myca -o output/dir/

or with `cargo run`

	cargo run -- -o output/dir

You can then use this same tool to view the output certificate's (or
any x509 certificate) contents.

	myca --parse path/to/cert.pem

## FAQ

#### What signature schemes are available?
Currently only RSA, but more will be made available promptly.
