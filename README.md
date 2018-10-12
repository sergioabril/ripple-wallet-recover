Ripple Go
=========

[Ripple Go](https://bitbucket.org/dchapes/ripple)
is a set of [Go](http://golang.org/) packages
for the [Ripple](https://ripple.com) payment network.
(I had also intended to clean up and open source my Ripple client here,
but that is now unlikely to ever happen).

[![GoDoc](https://godoc.org/bitbucket.org/dchapes/ripple?status.png)](https://godoc.org/bitbucket.org/dchapes/ripple)
[ ![Codeship Status for dchapes/ripple](https://codeship.io/projects/d4c658d0-3922-0132-ffeb-4eb13bd0ee77/status)](https://codeship.io/projects/42157)

Online package documentation is available via
[https://godoc.org/bitbucket.org/dchapes/ripple](https://godoc.org/bitbucket.org/dchapes/ripple).

To use:

1. Install [Go](http://golang.org/doc/install) (v1.2+ required),
   [mercurial](http://mercurial.selenic.com/), and
   [git](http://gitscm.com/).

2. Make sure [`GOPATH` is set](http://golang.org/doc/code.html#GOPATH)
   correctly.¹

3. Fetch this repository into your `GOPATH` ready for use
   (the `...` grabs everything, or you could select individual packages²):

		go get bitbucket.org/dchapes/ripple/...

4. Run all the tests (optional):

		go test bitbucket.org/dchapes/ripple/...

5. Check the [documentation](http://godoc.org/bitbucket.org/dchapes/ripple)
   to see what you can do with it.

If the above `go get` fails, or you have dependency issues building/testing this,
it is usually due to
[incorrect `GOROOT` and/or `GOPATH` settings](http://golang.org/doc/code.html#GOPATH).
If the build fails check that you have at least go1.2 (run `go version`).

---

Later, when this repository is updated, you can get the latest version/changes
using one of these methods:

- Manual mercurial commands:

    `cd ${your_first_GOPATH_directory}/src/bitbucket.org/dchapes/ripple;
    hg pull -u`

    This will pull down the latest change sets and attempt to update your working directory.
    Dependencies are not updated.
    The advantage of this method is that you can use the various mercurial commands to
    manage any local changes, merges, etc.
    See `hg pull -h` for more information.

- Using Go:

    `go get -v -u bitbucket.org/dchapes/ripple/...`

    The `-u` option should cause Go to update the named packages
    and their dependencies.
    See `go get -h` for more information.

---

All code contained within this repository (in particular the code under
`crypto` and `crypto/ccm`, probably the only thing anyone might be
interesed in) is licensed under a simplified BSD 2-clause license, see
the LICENSE file for details.

---

¹ `go help GOPATH` also has information on GOPATH.

² If you just want to install a single command,
e.g. the [wallet-simple](http://godoc.org/bitbucket.org/dchapes/ripple/cmd/wallet-simple) command,
you can just do step 1&2 as above,
then run `go get bitbucket.org/dchapes/ripple/cmd/wallet-simple`.
An executable should be built and put in the `bin` sub-directory of the first directory
listing in your `GOPATH`.
