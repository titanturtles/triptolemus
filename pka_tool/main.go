package main

import (
	"bytes"
	"compress/zlib"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/twofish"
)

// Ports pktctl's pktfile decode: unscramble -> Twofish-EAX open -> mask -> zlib.
var KEY = bytes.Repeat([]byte{0x89}, 16)   // {137}*16
var NONCE = bytes.Repeat([]byte{0x10}, 16) // {16}*16

func lowByte(v uint64) byte { return byte(v & 0xFF) }

func unscramble(file []byte) []byte {
	n := len(file)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = file[n-1-i] ^ lowByte(uint64(n)-uint64(i)*uint64(n))
	}
	return out
}

func mask(data []byte) {
	n := len(data)
	for i := 0; i < n; i++ {
		data[i] ^= lowByte(uint64(n) - uint64(i))
	}
}

func dbl(b []byte) []byte {
	out := make([]byte, 16)
	carry := byte(0)
	for i := 15; i >= 0; i-- {
		out[i] = (b[i] << 1) | carry
		carry = b[i] >> 7
	}
	if b[0]&0x80 != 0 {
		out[15] ^= 0x87
	}
	return out
}

func cmac(c cipher.Block, msg []byte) []byte {
	L := make([]byte, 16)
	c.Encrypt(L, make([]byte, 16))
	k1 := dbl(L)
	k2 := dbl(k1)

	var last []byte
	n := len(msg)
	nblocks := (n + 15) / 16
	if nblocks == 0 {
		nblocks = 1
	}
	complete := n > 0 && n%16 == 0
	x := make([]byte, 16)
	for i := 0; i < nblocks; i++ {
		start := i * 16
		if i == nblocks-1 {
			var m []byte
			if complete {
				m = xor(msg[start:start+16], k1)
			} else {
				rem := msg[start:]
				padded := make([]byte, 16)
				copy(padded, rem)
				padded[len(rem)] = 0x80
				m = xor(padded, k2)
			}
			last = xor(x, m)
		} else {
			x = xorEnc(c, x, msg[start:start+16])
		}
	}
	out := make([]byte, 16)
	c.Encrypt(out, last)
	return out
}

func xor(a, b []byte) []byte {
	o := make([]byte, len(a))
	for i := range a {
		o[i] = a[i] ^ b[i]
	}
	return o
}

func xorEnc(c cipher.Block, x, blk []byte) []byte {
	o := make([]byte, 16)
	c.Encrypt(o, xor(x, blk))
	return o
}

// omac(domain, data) = CMAC(prefix || data), prefix = 16 zero bytes with last = domain.
func omac(c cipher.Block, domain byte, data []byte) []byte {
	prefix := make([]byte, 16)
	prefix[15] = domain
	return cmac(c, append(prefix, data...))
}

func xor3(a, b, d []byte) []byte { return xor(xor(a, b), d) }

// firstPassHash returns the activity's stored password hash (PASS="<32hex>"), or "".
func firstPassHash(xml []byte) string {
	m := regexp.MustCompile(`PASS="([0-9A-Fa-f]{32})"`).FindSubmatch(xml)
	if m == nil {
		return ""
	}
	return strings.ToUpper(string(m[1]))
}

// slugImage turns a .pka filename into a sarpedon-safe image name (^[A-Za-z0-9-_ ]+$).
func slugImage(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	var sb strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			sb.WriteRune(r)
		case r == ' ':
			sb.WriteRune('-')
		}
	}
	return "PT-" + sb.String()
}

func genKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "ptk_" + hex.EncodeToString(b)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  pka_tool -pass <in.pka>           print the activity password hash")
	fmt.Fprintln(os.Stderr, "  pka_tool -conf <in.pka> [image]   print ready config blocks for a new activity")
	fmt.Fprintln(os.Stderr, "  pka_tool <in.pka> <out.xml>       decrypt the activity to XML")
	os.Exit(2)
}

func main() {
	// Modes: -pass (hash only), -conf (ready config blocks), default (decrypt to XML).
	mode, inPath, outPath, imageArg := "xml", "", "", ""
	switch {
	case len(os.Args) >= 3 && os.Args[1] == "-pass":
		mode, inPath = "pass", os.Args[2]
	case len(os.Args) >= 3 && os.Args[1] == "-conf":
		mode, inPath = "conf", os.Args[2]
		if len(os.Args) >= 4 {
			imageArg = os.Args[3]
		}
	case len(os.Args) >= 3:
		mode, inPath, outPath = "xml", os.Args[1], os.Args[2]
	default:
		usage()
	}
	file, err := os.ReadFile(inPath)
	if err != nil {
		panic(err)
	}
	c, err := twofish.NewCipher(KEY)
	if err != nil {
		panic(err)
	}

	sealed := unscramble(file)
	if len(sealed) < 16 {
		panic("too short")
	}
	tag := sealed[len(sealed)-16:]
	sealed = sealed[:len(sealed)-16]

	nonceMac := omac(c, 0, NONCE)
	headerMac := omac(c, 1, nil)
	dataMac := omac(c, 2, sealed) // over ciphertext
	expected := xor3(nonceMac, headerMac, dataMac)
	if !bytes.Equal(expected, tag) {
		fmt.Fprintln(os.Stderr, "WARNING: EAX tag mismatch (decryption may be wrong)")
	} else {
		fmt.Fprintln(os.Stderr, "EAX tag OK (decryption verified)")
	}

	// CTR decrypt with IV = nonceMac (CTR128BE)
	ctr := cipher.NewCTR(c, nonceMac)
	ctr.XORKeyStream(sealed, sealed)

	mask(sealed)

	if len(sealed) < 4 {
		panic("too short after decrypt")
	}
	size := binary.BigEndian.Uint32(sealed[:4])
	zr, err := zlib.NewReader(bytes.NewReader(sealed[4:]))
	if err != nil {
		panic(fmt.Sprintf("zlib: %v", err))
	}
	xml, err := io.ReadAll(zr)
	if err != nil && len(xml) == 0 {
		panic(fmt.Sprintf("inflate: %v", err))
	}
	if uint32(len(xml)) > size {
		xml = xml[:size]
	}

	switch mode {
	case "pass":
		// The Activity Wizard password is stored as a 32-hex MD5 in PASS="...".
		// That stored hash is exactly what IPC confirmPassword wants.
		if h := firstPassHash(xml); h != "" {
			fmt.Println(h)
		} else {
			fmt.Fprintln(os.Stderr, "no activity password hash found (activity may be unlocked)")
		}

	case "conf":
		hash := firstPassHash(xml)
		image := imageArg
		if image == "" {
			image = slugImage(inPath)
		}
		key := genKey()
		label := strings.TrimSuffix(filepath.Base(inPath), filepath.Ext(inPath))
		ptLine := ",\n      \"pt_password\": " + fmt.Sprintf("%q", hash)
		note := ""
		if hash == "" {
			ptLine = ""
			note = "  (activity is UNLOCKED: no pt_password needed)"
		}
		fmt.Printf("# ===== 1) add to sarpedon.conf on the scoreboard (needs sudo) =====\n")
		fmt.Printf("[[image]]\nname = %q\ncolor = \"#1BA0E2\"\npassword = %q\n\n", image, key)
		fmt.Printf("# ===== 2) add one entry to \"activities\" in pt_agent.conf.json =====%s\n", note)
		fmt.Printf("    {\n")
		fmt.Printf("      \"label\": %q,\n", label)
		fmt.Printf("      \"pka\": %q,\n", filepath.Base(inPath))
		fmt.Printf("      \"image\": %q,\n", image)
		fmt.Printf("      \"password\": %q%s\n", key, ptLine)
		fmt.Printf("    }\n")

	default: // xml
		if err := os.WriteFile(outPath, xml, 0600); err != nil {
			panic(err)
		}
		fmt.Fprintf(os.Stderr, "wrote %d bytes of XML to %s\n", len(xml), outPath)
	}
}
