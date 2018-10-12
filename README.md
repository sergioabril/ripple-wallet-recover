Ripple Wallet Recover
=========

Ripple Wallet Recover is a fork of [Ripple Go](https://bitbucket.org/dchapes/ripple),
a set of [Go](http://golang.org/) packages
for the [Ripple](https://ripple.com) payment network, made by [dchapes](https://bitbucket.org/dchapes)

[![GoDoc](https://godoc.org/bitbucket.org/dchapes/ripple?status.png)](https://godoc.org/bitbucket.org/dchapes/ripple)
[ ![Codeship Status for dchapes/ripple](https://codeship.io/projects/d4c658d0-3922-0132-ffeb-4eb13bd0ee77/status)](https://codeship.io/projects/42157)

Online package documentation is available via
[https://godoc.org/bitbucket.org/dchapes/ripple](https://godoc.org/bitbucket.org/dchapes/ripple).

---

### What's new?

Instead of relying on single word inputs, It makes use of two text files, one for possible usernames and the other for possible passwords, making it easier to try a bunch of them really fast. I modified the original to recover my own ripple wallet. And it worked!

### Install

##### Option A, Binary (for macOS only):

1. Download the latest release from [HERE](https://github.com/sergioabril/ripple-wallet-recover/releases) 

2. Follow the instructions inside the zip file.

##### Option B, Download source:

1. Install [Go](http://golang.org/doc/install) (v1.2+ required),
   [mercurial](http://mercurial.selenic.com/), and
   [git](http://gitscm.com/).

2. Make sure [`GOPATH` is set](http://golang.org/doc/code.html#GOPATH)
   correctly.¹

3. Fetch this repository into your `GOPATH` ready for use:

		go get github.com/sergioabril/ripple-wallet-recover/wallet-recover

5. Check the [documentation](http://godoc.org/bitbucket.org/dchapes/ripple)
   to see what you can do with it.

If the above `go get` fails, or you have dependency issues building/testing this,
it is usually due to
[incorrect `GOROOT` and/or `GOPATH` settings](http://golang.org/doc/code.html#GOPATH).
If the build fails check that you have at least go1.2 (run `go version`).

---

All code contained within this repository (in particular the code under
`crypto` and `crypto/ccm`, probably the only thing anyone might be
interesed in) is licensed under a simplified BSD 2-clause license, see
the LICENSE file for details.

---
