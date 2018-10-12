// The wallet-recover command is the start of something to decode/encode
// wallet blobs as stored at Payward, in the local browser, or exported
// as ripple-wallet.txt.
//
// WARNING: this code is very rough and just thrown together to
// expermint with the blob files and make sure I was on the right track.
// I've had more perssing issues to deal with and I'm only making this
// available in this state as reference for anyone that would find it
// easier than look at or using the JavaScript ripple client.
//
// See https://ripple.com/forum/viewtopic.php?f=2&t=5227#p33011
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strconv"

	"bitbucket.org/dchapes/ripple/crypto/ccm"
	"golang.org/x/crypto/pbkdf2"
)

// encryptedBlob is the JSON struct that is the encrypted blob
type encryptedBlob struct {
	IV     base64data `json:"iv"`     // initilization vector or nonce for CCM mode
	V      int        `json:"v"`      // version?
	Iter   int        `json:"iter"`   // PBKDF2 iteration count
	KS     int        `json:"ks"`     // keysize in bits
	TS     int        `json:"ts"`     // CCM tag size in bits
	Mode   string     `json:"mode"`   // ccm, cbc, …
	AData  string     `json:"adata"`  // additional authenticated data
	Cipher string     `json:"cipher"` // aes, …
	Salt   base64data `json:"salt"`   //PBKDF2 salt
	CT     base64data `json:"ct"`     // ciphertext
}

// walletdata is the JSON struct of the decrypted wallet blob file
type walletdata struct {
	MasterSeed string `json:"master_seed"`
	AccountID  string `json:"account_id"` // redundant, can be calculated from MasterSeed
	Contacts   []struct {
		Name    string
		Address string
	} `json:"contacts"`
	PreferredIssuer       map[string]string `json:"preferred_issuer"`
	PreferredSecondIssuer map[string]string `json:"preferred_second_issuer"`
}

// base64data is a simple type to handle conversion between
// base64encoded strings and raw data bytes.
type base64data []byte

// MarshalText implements encoding.TextMarshaller and is used by the
// json when marshalling JSON.
func (b base64data) MarshalText() ([]byte, error) {
	text := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(text, b)
	return text, nil
}

// UnmarshalText implements encoding.TextUnmarshaller and is used by the
// json when unmarshalling JSON.
func (b *base64data) UnmarshalText(text []byte) error {
	if n := base64.StdEncoding.DecodedLen(len(text)); cap(*b) < n {
		*b = make([]byte, n)
	}
	n, err := base64.StdEncoding.Decode(*b, text)
	*b = (*b)[:n]
	return err
}

// int32Array is an hack used for some debug output to approximate
// what the JavaScript implementation will print/show when running
// it in a console.
func (b base64data) int32Array() []int32 {
	n := len(b) / 4
	extra := len(b) % 4
	if extra > 0 {
		n++
	}
	a := make([]int32, n)
	i, j := 0, 0
	for ; j < extra; j++ {
		a[i] <<= 8
		a[i] |= int32(b[j])
	}
	if j != 0 {
		i++
	}
	for ; i < len(a); i++ {
		a[i] = int32(b[j]) << 24
		a[i] |= int32(b[j+1]) << 16
		a[i] |= int32(b[j+2]) << 8
		a[i] |= int32(b[j+3])
		j += 4
	}
	return a
}

func (b base64data) int64Array() []int64 {
	a := make([]int64, 0, (len(b)/4)+1)
	var tmp int64
	for i, bi := range b {
		tmp <<= 8
		tmp |= int64(bi)
		if i%4 == 3 {
			a = append(a, tmp)
			tmp = 0
		}
	}
	if i := uint(len(b) % 4); i != 0 {
		tmp <<= 8 * (4 - i)
		tmp |= int64(0x10000000000) * int64(i<<3)
		a = append(a, tmp)
	}
	return a
}

func (b base64data) debug(name string) {
	log.Printf("%s: len=%d, 0x%x = %q = %v",
		name, len(b), b, b.xString(), b.int32Array())
}

func debug(name string, d []byte) {
	b := base64data(d)
	log.Printf("%s: len=%d, 0x%x = %q = %v",
		name, len(d), d, string(d), b.int32Array())
}

// ... not used, was the String() function to implement fmt.Stringer
func (b base64data) xString() string {
	text := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(text, b)
	return string(text)
	//return fmt.Sprintf("%s = %v", text, b.int32Array())
}

func main() {
	walletFlag := flag.String("wallet", "ripple-wallet.txt", "input wallet filename, empty for stdin")
	jsonFlag := flag.Bool("json", false, "dump the encrypted wallet JSON data")
	nameFlag := flag.String("name", "", "wallet name (required)")
	passFlag := flag.String("pass", "", "pass-phrase (required)")
	stubFlag := flag.String("stub", "", "filename to write out a stubbed wallet")
	flag.Parse()

	if flag.NArg() != 0 || *nameFlag == "" || *passFlag == "" {
		flag.Usage()
		os.Exit(2) // match the exit code used by flag code should be EX_USAGE
	}

	// f is a io.Reader of the raw blob data
	var f *os.File
	var err error
	if *walletFlag == "" {
		f = os.Stdin
		log.Println("Reading from stdin")
	} else {
		f, err = os.Open(*walletFlag)
		if err != nil {
			log.Fatalf("Opening %q: %v", *walletFlag, err)
		}
		defer f.Close()
		log.Printf("Opened file %q", *walletFlag)
	}
	// base64Decoder is an io.Reader of the base64 decoded blob
	base64Decoder := base64.NewDecoder(base64.StdEncoding, f)

	if *jsonFlag {
		buf, err := ioutil.ReadAll(base64Decoder)
		if err != nil {
			log.Fatal("Reading:", err)
		}
		log.Println("Decoded", len(buf), "bytes")
		log.Printf("Raw data:\n%s", buf)
		pp := new(bytes.Buffer)
		err = json.Indent(pp, buf, "", "    ")
		if err != nil {
			log.Fatal("indent JSON failed:", err)
		}
		fmt.Println(pp)
		// XXX already decoded but keeps the later code happy
		base64Decoder = bytes.NewBuffer(buf)
	}

	jsonDecoder := json.NewDecoder(base64Decoder)
	eBlob := new(encryptedBlob)
	err = jsonDecoder.Decode(&eBlob)
	if err != nil {
		log.Fatal("JSON decoder:", err)
	}

	// now eBlob is a encryptedBlob struct with it's fields decoded
	// and filled in.
	// The eBlob.CT field is encrypted as specified by the Cipher,
	// Mode, and other fields.

	eBlob.IV.debug("IV")
	eBlob.Salt.debug("salt")
	log.Print("len(ciphertext):", len(eBlob.CT))
	//eBlob.CT.debug("CT")
	if n := len(eBlob.CT); n > 20 {
		log.Printf("ciphertext %x…%x", eBlob.CT[:10], eBlob.CT[n-10:])
	}

	if true {
		// This is the hash used for storage/lookup both in the
		// local browser and at Payward.
		blobHash := sha256.Sum256([]byte(*nameFlag + *passFlag))
		log.Printf("blobHash: %x", blobHash)
	}
	passkey := strconv.Itoa(len(*nameFlag)) + "|" + *nameFlag + *passFlag
	//passkey = *nameFlag + *passFlag // old bad method
	log.Println("passkey:", passkey)
	debug("passkey:", []byte(passkey))

	key := pbkdf2.Key([]byte(passkey), eBlob.Salt, eBlob.Iter, eBlob.KS/8, sha256.New)
	debug("key", key)

	var cb cipher.Block
	switch eBlob.Cipher {
	case "aes":
		cb, err = aes.NewCipher(key)
		if err != nil {
			log.Fatal("Error initializing AES:", err)
		}
	default:
		log.Fatalf("Blob encrypted with unsupported cipher %q", eBlob.Cipher)
	}
	//log.Println("cipher:", cb)

	var authmode cipher.AEAD
	nonce := []byte(eBlob.IV)
	switch eBlob.Mode {
	case "ccm":
		log.Println("tagsize:", eBlob.TS)
		if eBlob.TS%8 != 0 {
			log.Fatalf("bad tag size TS=%d, not a multiple of 8", eBlob.TS)
		}
		nlen := ccm.MaxNonceLength(len(eBlob.CT) - eBlob.TS/8)
		log.Println("max nlen:", nlen)
		if nlen > len(nonce) {
			nlen = len(nonce)
		} else {
			nonce = nonce[:nlen]
		}
		log.Println("nlen:", nlen)
		debug("nonce", nonce)
		c, err := ccm.NewCCM(cb, eBlob.TS/8, nlen)
		if err != nil {
			log.Fatal("Error initializing CCM mode:", err)
		}
		log.Println("ccm MaxLength:", c.MaxLength())
		authmode = c
	case "cbc":
		log.Println("WARNING: using CBC mode, data cannot be authenticated")
		fallthrough // not supported
	default:
		log.Fatalf("Blob encrypted with unsupported cipher mode %q", eBlob.Mode)
		//case "ocb2":
	}
	log.Println("authmode:", authmode)

	debug("adata", []byte(eBlob.AData))
	adata, _ := url.QueryUnescape(eBlob.AData) // XXX
	debug("adata", []byte(adata))

	blob, err := authmode.Open(nil, nonce, eBlob.CT, []byte(adata))
	if err != nil {
		log.Fatal("error decrypting and authenticating blob:", err)
	}
	log.Printf("blob: %q", blob)

	if *jsonFlag {
		pp := new(bytes.Buffer)
		err = json.Indent(pp, blob, "", "    ")
		if err != nil {
			log.Fatal("indent JSON failed:", err)
		}
		fmt.Println(pp)
	}

	wallet := new(walletdata)
	err = json.Unmarshal(blob, wallet)
	if err != nil {
		log.Fatal("JSON unmarshal failed:", err)
	}

	fmt.Printf("Wallet data: %v\n", *wallet)

	// ****************
	// experiment at re-encrypted a changed blob

	wallet.MasterSeed = "sp6JS7f14BuwFY8Mw6bTtLKWauoUs" // The zero seed, should render the blob unusable?
	newBlob, err := json.Marshal(wallet)
	if err != nil {
		log.Fatal("JSON marshal failed:", err)
	}

	newEncBlob := new(encryptedBlob)
	*newEncBlob = *eBlob

	newEncBlob.IV = make([]byte, 16)
	_, err = rand.Read(newEncBlob.IV)
	if err != nil {
		log.Fatal("crypto/rand Read failed:", err)
	}
	newEncBlob.IV.debug("newIV")

	newEncBlob.CT = authmode.Seal(nil, newEncBlob.IV[:13], newBlob, []byte(newEncBlob.AData))

	//var outf *os.File
	var outw io.Writer
	if *stubFlag == "" {
		//outw = os.Stdout
		outw = ioutil.Discard
	} else {
		outf, err := os.Create(*stubFlag)
		if err != nil {
			log.Fatalf("Opening/creating %q: %v", *stubFlag, err)
		}
		defer outf.Close()
		log.Printf("Opened and truncated file %q", *stubFlag)
		outw = outf
	}
	base64Encoder := base64.NewEncoder(base64.StdEncoding, outw)
	jsonEncoder := json.NewEncoder(base64Encoder)
	err = jsonEncoder.Encode(newEncBlob)
	if err != nil {
		log.Fatal("JSON encoder:", err)
	}

	//err = jsonEncoder.Close()
	err = base64Encoder.Close()
	if err != nil {
		log.Fatal("close:", err)
	}
	log.Println("EOF")
}
