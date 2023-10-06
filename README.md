# myca

My CA is a developer tool to generate TLS certificate chains. It is
meant to be used in developers workflow, and can currently generate
certificate chain consisting of 1 Root CA and 1 end-entity
certificate, along with end-entity's private key. End-entity will be
signed by Root CA. These have been shown to function with rustls
validation, verification and encryption, but there is still much to
improve so use with caution.

## features

  * easy
  * flexible

## usage
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

  * pkcs\_rsa\_sha256
  * pkcs\_ecdsa\_p256\_sha256
  * pkcs\_ed25519
  * **more to come**

#### Why can't my client authenticate with server?

Make sure you pass `--clientauth` when generating certificate for
client authentication.

#### How do I use this for mutual authentication?

Essentially, run `myca` twice. Copy `root-ca.pem` to the *authticator*
and copy `cert.pem` and `cert.key.pem` to the thing desiring
authentication. That is probably not a very good explanation. Let me
think about it and ask again later.
## justification

Self-signed certificates are great, but they don't allow you to test
authentication. Openssl wrapped in bash is great, but you have to know
many things to output a valid certificate chain. As your application
evolves, you may find your collection of bash scripts has grows with
it. This tool is mean to be easy enough to generate a valid
certificate chain by only supplying a directory to output them into,
and flexible enough that you can easily modify the parameters you
need.

## help

	myca --help
