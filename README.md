# myca

My CA is a developer tool to generate TLS certificate chains. It is
meant to be used in developer workflow, and can currently generate
certificate chain consisting of 1 Root CA and 1 end-entity
certificate, along with private keys. End-entity will be
signed by Root CA.

## features

  * easy
  * tested
  * flexible

## installation
Easiest method is currently `cargo install myca`. You can also clone
this repo and build it with `cargo build`.

## usage
Having compiled the binary you can simply pass a path to output
generated files.

	myca -o output/dir/

I the output directory you will find these files:

  * `cert.pem`  (end-entity's X509 certficate, signed by `root-ca`'s key)
  * `cert.key.pem` (end-entity's private key)
  * `root-ca.pem` (ca's self-signed x509 certificate)
  * `root-ca.key.pem` (ca's private key)

The `root-ca.key.pem` is only present in case you want to do something
later with it like sign more end-entity certficates. If you plan on
using these files as anything more than temporary throw away secrets
for testing/development, you should be very careful what you do with
it. If you don't need it, destroy it.

or with `cargo run`

	cargo run -- -o output/dir

You can then use this same tool to view the output certificate's (or
any x509 certificate) contents.

	myca --parse path/to/cert.pem

For complete list of supported options:

	myca --help

## FAQ

#### What signature schemes are available?

  * pkcs\_ecdsa\_p256\_sha256
  * pkcs\_ecdsa\_p384\_sha384
  * pkcs\_ed25519
  * pkcs\_rsa\_sha256
  * pkcs\_rsa\_sha384
  * pkcs\_rsa\_sha512

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
evolves, your collection of bash scripts may become large and
difficult to maintain. This tool is mean to be easy enough to generate
a valid certificate chain by only supplying a directory to output them
into, and flexible enough that you can easily modify the parameters
you need.
