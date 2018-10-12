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
	//"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	//"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strconv"
	"bufio" //To scan words on a file
	"strings"

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
	nameFlag := flag.String("namelist", "names.txt", "specify wallet name list filename")
	passFlag := flag.String("passlist", "words.txt", "specify password list filename")
	//stubFlag := flag.String("stub", "", "filename to write out a stubbed wallet")
	flag.Parse()

	if flag.NArg() != 0 || *nameFlag == "" || *passFlag == "" {
		flag.Usage()
		os.Exit(2) // match the exit code used by flag code should be EX_USAGE
	}



	//READ NAMES FILE
	var g *os.File
	var errn error
	var names []string
	if *nameFlag == "" {
		g = os.Stdin
		log.Fatalf("You need to specify a file containing possible names")
	} else {
		g, errn = os.Open(*nameFlag)
		if errn != nil {
			log.Fatalf("Opening %q: %v", *nameFlag, errn)
		}
		defer g.Close()
		//log.Printf("Opened file %q", *walletFlag)

		//Scan Words
		scanner := bufio.NewScanner(g)
		scanner.Split(bufio.ScanWords)

		for scanner.Scan() {
			names = append(names, scanner.Text())
		}

		//fmt.Println("Names list:")
		//for _, word := range names {
			//fmt.Println(word)
		//}
	}

	//READ PASSWORDS
	var h *os.File
	var errp error
	var passwords []string
	if *passFlag == "" {
		h = os.Stdin
		log.Fatalf("You need to specify a file containing possible names")
	} else {
		h, errp = os.Open(*passFlag)
		if errp != nil {
			log.Fatalf("Opening %q: %v", *passFlag, errp)
		}
		defer h.Close()
		//log.Printf("Opened file %q", *walletFlag)

		//Scan Words
		scanner := bufio.NewScanner(h)
		scanner.Split(bufio.ScanWords)

		for scanner.Scan() {
			passwords = append(passwords, scanner.Text())
		}

		//fmt.Println("Password list:")
		//for _, word := range passwords {
			//fmt.Println(word)
		//}
	}


	//Two kind of possible key generation //0 old , 1 new
	keymethods := []int{0, 1}



	///
	/// Here start the loop to bruteforce the wallet
	///

	for _, possiblename := range names {

		for _, possiblepass := range passwords {

			for _, usedkeymethod := range keymethods {

				// READ WALLET FILE (ideally, it should be done only once, outside this loop)
				// f is a io.Reader of the raw blob data
				var f *os.File
				var err error
				if *walletFlag == "" {
					f = os.Stdin
					//log.Println("Reading from stdin")
				} else {
					f, err = os.Open(*walletFlag)
					if err != nil {
						log.Fatalf("Opening %q: %v", *walletFlag, err)
					}
					//defer f.Close() //no need to defer, it's called later
					//log.Printf("Opened file %q", *walletFlag)
				}
				// base64Decoder is an io.Reader of the base64 decoded blob
				base64Decoder := base64.NewDecoder(base64.StdEncoding, f)


				//Work with wallet file
				if *jsonFlag {
					buf, err := ioutil.ReadAll(base64Decoder)
					if err != nil {
						log.Fatal("Reading:", err)
					}
					//log.Println("Decoded", len(buf), "bytes")
					//log.Printf("Raw data:\n%s", buf)
					pp := new(bytes.Buffer)
					err = json.Indent(pp, buf, "", "    ")
					if err != nil {
						log.Fatal("indent JSON failed:", err)
					}
					//fmt.Println(pp)
					// XXX already decoded but keeps the later code happy
					base64Decoder = bytes.NewBuffer(buf)
				}

				jsonDecoder := json.NewDecoder(base64Decoder)
				eBlobOG := new(encryptedBlob)
				errorjson := jsonDecoder.Decode(&eBlobOG)
				if errorjson != nil {
					log.Fatal("JSON decoder Error:", errorjson)
				}

				//Close Wallet file, otherwise it would reach a limit of open files.
				f.Close()

				//Prepare new eBlob (I could use eBlobOG, but I was doing some tests)
				//eBlob := new(encryptedBlob)
				var eBlob = eBlobOG


				//Prepare passwords
				fixedname := strings.TrimSpace(possiblename)
				fixedpass := strings.TrimSpace(possiblepass)

				//Prepare key: What method?
				passkey := ""
				if usedkeymethod==0 {
					//OLD
					passkey = fixedname + fixedpass // old bad method
				}else{
					//NEW:
					passkey = strconv.Itoa(len(fixedname)) + "|" + fixedname + fixedpass
				}


				//log.Println("passkey:",passkey)
				//debug("passkey:", []byte(passkey))

				key := pbkdf2.Key([]byte(passkey), eBlob.Salt, eBlob.Iter, eBlob.KS/8, sha256.New)
				//debug("key", key)

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
					//log.Println("tagsize:", eBlob.TS)
					if eBlob.TS%8 != 0 {
						log.Fatalf("bad tag size TS=%d, not a multiple of 8", eBlob.TS)
					}
					nlen := ccm.MaxNonceLength(len(eBlob.CT) - eBlob.TS/8)
					//log.Println("max nlen:", nlen)
					if nlen > len(nonce) {
						nlen = len(nonce)
					} else {
						nonce = nonce[:nlen]
					}
					//log.Println("nlen:", nlen)
					//debug("nonce", nonce)
					c, err := ccm.NewCCM(cb, eBlob.TS/8, nlen)
					if err != nil {
						log.Fatal("Error initializing CCM mode:", err)
					}
					//log.Println("ccm MaxLength:", c.MaxLength())
					authmode = c
				case "cbc":
					log.Println("WARNING: using CBC mode, data cannot be authenticated")
					fallthrough // not supported
				default:
					log.Fatalf("Blob encrypted with unsupported cipher mode %q", eBlob.Mode)
					//case "ocb2":
				}
				//log.Println("authmode:", authmode)

				//debug("adata", []byte(eBlob.AData))
				adata, _ := url.QueryUnescape(eBlob.AData) // XXX
				//debug("adata", []byte(adata))

				blob, errordecr := authmode.Open(nil, nonce, eBlob.CT, []byte(adata))
				if errordecr != nil {
					//IF IT FAILS, I JUST WANT TO CONTINUE WITH THE NEXT ONE, DOn'T EXIT
					//log.Fatal("Error decrypting and authenticating blob:", err)
					fmt.Print(".")
					errordecr = nil
					continue
				}
				//log.Printf("blob: %q", blob)

				if *jsonFlag {
					pp := new(bytes.Buffer)
					err = json.Indent(pp, blob, "", "    ")
					if err != nil {
						log.Fatal("Password worked, but indent JSON failed:", err)
					}
					//fmt.Println(pp)
				}

				wallet := new(walletdata)
				err = json.Unmarshal(blob, wallet)
				if err != nil {
					log.Fatal("Password worked, but JSON unmarshal failed:", err)
				}
				fmt.Printf("\n")
				log.Printf("Success!")
				log.Printf("Username: %q", possiblename)
				log.Printf("Password: %q", possiblepass)
				log.Printf("Seed: %q", wallet.MasterSeed)
				log.Printf("Account id: %q", wallet.AccountID)

				//Force exit so it ends here.
				os.Exit(0)
				//fmt.Printf("Wallet data: %v\n", *wallet)
				//log.Println("EOF")
			}
		}

	}

	fmt.Printf("\nEnded without any match. Sorry.\n")

}
