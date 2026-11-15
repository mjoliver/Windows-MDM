// Package msi parses Windows Installer (.msi) OLE Compound File Binary (CFB)
// packages in pure Go (no CGO or Windows-only DLLs) to extract ProductCode,
// ProductName, ProductVersion, Manufacturer, UpgradeCode, and SHA-256 FileHash.
package msi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	maxMSIInspectBytes = 1 << 30 // 1 GiB safety cap for remote MSI inspection
	msiNameAlphabet    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._!"
	endOfChain         = -2 // 0xFFFFFFFE
	freeSect           = -1 // 0xFFFFFFFF
)

var (
	cfbMagic      = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	productCodeRE = regexp.MustCompile(`^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$`)
	sha256HexRE   = regexp.MustCompile(`^[0-9A-F]{64}$`)
)

// Metadata holds extracted MSI package attributes and cryptographic digest.
type Metadata struct {
	ProductCode    string `json:"product_code"`
	ProductName    string `json:"name"`
	ProductVersion string `json:"version"`
	Manufacturer   string `json:"publisher"`
	UpgradeCode    string `json:"upgrade_code"`
	SHA256         string `json:"sha256"`
	FileSizeBytes  int64  `json:"file_size_bytes"`
}

// NormalizeProductCode validates and canonicalizes an MSI ProductCode GUID into
// uppercase "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" format.
func NormalizeProductCode(raw string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if s == "" {
		return "", errors.New("product_code is required")
	}
	if !strings.HasPrefix(s, "{") {
		s = "{" + s
	}
	if !strings.HasSuffix(s, "}") {
		s = s + "}"
	}
	if !productCodeRE.MatchString(s) {
		return "", fmt.Errorf("invalid MSI ProductCode %q (expected {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX})", raw)
	}
	return s, nil
}

// NormalizeSHA256 validates and canonicalizes a 64-character SHA-256 hex digest.
func NormalizeSHA256(raw string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	if !sha256HexRE.MatchString(s) {
		return "", fmt.Errorf("invalid SHA-256 hex digest (expected 64 hex characters)")
	}
	return s, nil
}

// ValidateContentURL ensures an MSI download URL uses HTTPS without embedded
// credentials and does not target a loopback, private, or link-local IP literal.
func ValidateContentURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("content_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid content_url: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("content_url must use https://")
	}
	if u.User != nil {
		return errors.New("content_url must not contain user credentials")
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return errors.New("content_url is missing hostname")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("content_url IP %s is not permitted", ip.String())
		}
	}
	return nil
}

func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// NewIdentityHTTPClient returns an SSRF-hardened HTTPS client with automatic
// gzip compression disabled (DisableCompression: true). Omitting Accept-Encoding
// prevents CDNs such as dl.google.com from serving Content-Encoding: gzip on
// HTTP 206 byte-range slices (which breaks Windows 11 Delivery Optimization).
func NewIdentityHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableCompression:    true,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
				Control: func(_, address string, _ syscall.RawConn) error {
					host, _, err := net.SplitHostPort(address)
					if err != nil {
						return err
					}
					if ip := net.ParseIP(host); ip != nil && isBlockedIP(ip) {
						return fmt.Errorf("blocked SSRF target IP %s", ip.String())
					}
					return nil
				},
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects fetching MSI")
			}
			return ValidateContentURL(req.URL.String())
		},
	}
}

// InspectRemoteURL downloads an HTTPS .msi file to a temporary file, computes
// its SHA-256 hash, and extracts MSI Property table metadata.
func InspectRemoteURL(ctx context.Context, rawURL string) (*Metadata, error) {
	if err := ValidateContentURL(rawURL); err != nil {
		return nil, err
	}
	return inspectURLWithClient(ctx, rawURL, NewIdentityHTTPClient(3*time.Minute))
}

func inspectURLWithClient(ctx context.Context, rawURL string, client *http.Client) (*Metadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building MSI download request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading MSI: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MSI download returned HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "latchz-msi-*.msi")
	if err != nil {
		return nil, fmt.Errorf("creating temp MSI file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	hasher := sha256.New()
	limited := io.LimitReader(resp.Body, maxMSIInspectBytes+1)
	written, err := io.Copy(io.MultiWriter(tmp, hasher), limited)
	if err != nil {
		return nil, fmt.Errorf("reading MSI stream: %w", err)
	}
	if written > maxMSIInspectBytes {
		return nil, fmt.Errorf("MSI exceeds %d MiB inspection limit", maxMSIInspectBytes>>20)
	}

	meta, err := InspectReaderAt(tmp, written)
	if err != nil {
		return nil, err
	}
	meta.SHA256 = strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))
	meta.FileSizeBytes = written
	return meta, nil
}

type dirEntry struct {
	name     string
	objType  byte
	startSec int32
	size     int64
}

// InspectReaderAt parses an MS-CFB (.msi) container and extracts metadata from
// its internal Property table.
func InspectReaderAt(r io.ReaderAt, totalSize int64) (*Metadata, error) {
	if totalSize < 512 {
		return nil, errors.New("file is too small to be a valid MSI package")
	}

	var hdr [512]byte
	if _, err := r.ReadAt(hdr[:], 0); err != nil {
		return nil, fmt.Errorf("reading MSI header: %w", err)
	}
	if !bytes.Equal(hdr[:8], cfbMagic) {
		return nil, errors.New("file is not a valid OLE Compound File (.msi)")
	}

	sectorShift := binary.LittleEndian.Uint16(hdr[30:32])
	if sectorShift != 9 && sectorShift != 12 {
		return nil, fmt.Errorf("unsupported CFB sector shift %d", sectorShift)
	}
	sectorSize := int(1 << sectorShift)

	miniShift := binary.LittleEndian.Uint16(hdr[32:34])
	if miniShift == 0 || miniShift > sectorShift {
		return nil, fmt.Errorf("invalid CFB mini-sector shift %d", miniShift)
	}
	miniSize := int(1 << miniShift)

	numFatSectors := int(int32(binary.LittleEndian.Uint32(hdr[44:48])))
	firstDirSec := int32(binary.LittleEndian.Uint32(hdr[48:52]))
	miniCutoff := int64(binary.LittleEndian.Uint32(hdr[56:60]))
	firstMiniFatSec := int32(binary.LittleEndian.Uint32(hdr[60:64]))
	numMiniFatSectors := int(int32(binary.LittleEndian.Uint32(hdr[64:68])))
	firstDifatSec := int32(binary.LittleEndian.Uint32(hdr[68:72]))
	numDifatSectors := int(int32(binary.LittleEndian.Uint32(hdr[72:76])))

	readSector := func(sec int32) ([]byte, error) {
		if sec < 0 {
			return nil, fmt.Errorf("negative CFB sector index %d", sec)
		}
		off := int64(sec+1) * int64(sectorSize)
		if off+int64(sectorSize) > totalSize {
			// Allow partial trailing sector at EOF
			if off >= totalSize {
				return nil, fmt.Errorf("CFB sector %d out of bounds", sec)
			}
			buf := make([]byte, sectorSize)
			_, err := r.ReadAt(buf[:totalSize-off], off)
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			return buf, nil
		}
		buf := make([]byte, sectorSize)
		if _, err := r.ReadAt(buf, off); err != nil {
			return nil, err
		}
		return buf, nil
	}

	// 1. Collect DIFAT sector pointers (109 in header + optional chained DIFAT sectors)
	difat := make([]int32, 0, numFatSectors)
	for i := 0; i < 109 && len(difat) < numFatSectors; i++ {
		sec := int32(binary.LittleEndian.Uint32(hdr[76+i*4 : 80+i*4]))
		if sec == freeSect || sec == endOfChain {
			break
		}
		difat = append(difat, sec)
	}
	difatSec := firstDifatSec
	for d := 0; d < numDifatSectors && difatSec >= 0 && len(difat) < numFatSectors; d++ {
		buf, err := readSector(difatSec)
		if err != nil {
			return nil, fmt.Errorf("reading DIFAT sector: %w", err)
		}
		entriesPerDifat := (sectorSize / 4) - 1
		for i := 0; i < entriesPerDifat && len(difat) < numFatSectors; i++ {
			sec := int32(binary.LittleEndian.Uint32(buf[i*4 : (i+1)*4]))
			if sec >= 0 {
				difat = append(difat, sec)
			}
		}
		difatSec = int32(binary.LittleEndian.Uint32(buf[sectorSize-4:]))
	}

	// 2. Build FAT array
	intsPerSector := sectorSize / 4
	fat := make([]int32, 0, len(difat)*intsPerSector)
	for _, fsec := range difat {
		buf, err := readSector(fsec)
		if err != nil {
			return nil, fmt.Errorf("reading FAT sector: %w", err)
		}
		for i := 0; i < intsPerSector; i++ {
			fat = append(fat, int32(binary.LittleEndian.Uint32(buf[i*4:(i+1)*4])))
		}
	}

	readChain := func(startSec int32, limitBytes int64) ([]byte, error) {
		var out bytes.Buffer
		sec := startSec
		visited := 0
		maxHops := len(fat) + 1
		for sec >= 0 && (limitBytes < 0 || int64(out.Len()) < limitBytes) {
			visited++
			if visited > maxHops || int(sec) >= len(fat) {
				return nil, errors.New("corrupt CFB FAT chain")
			}
			buf, err := readSector(sec)
			if err != nil {
				return nil, err
			}
			if limitBytes >= 0 {
				rem := limitBytes - int64(out.Len())
				if rem < int64(len(buf)) {
					out.Write(buf[:rem])
					break
				}
			}
			out.Write(buf)
			sec = fat[sec]
		}
		return out.Bytes(), nil
	}

	// 3. Read Directory entries
	dirBytes, err := readChain(firstDirSec, -1)
	if err != nil {
		return nil, fmt.Errorf("reading CFB directory: %w", err)
	}

	var rootEntry *dirEntry
	streams := make(map[string]dirEntry)
	for off := 0; off+128 <= len(dirBytes); off += 128 {
		entry := dirBytes[off : off+128]
		objType := entry[66]
		nameByteLen := int(binary.LittleEndian.Uint16(entry[64:66]))
		if objType == 0 || nameByteLen < 2 || nameByteLen > 64 {
			continue
		}
		name := decodeMSIStreamName(entry[:nameByteLen])
		startSec := int32(binary.LittleEndian.Uint32(entry[116:120]))
		var size int64
		if sectorShift == 9 {
			size = int64(binary.LittleEndian.Uint32(entry[120:124]))
		} else {
			size = int64(binary.LittleEndian.Uint64(entry[120:128]))
		}
		de := dirEntry{name: name, objType: objType, startSec: startSec, size: size}
		if objType == 5 && rootEntry == nil {
			rootCopy := de
			rootEntry = &rootCopy
		} else if objType == 2 {
			streams[name] = de
		}
	}

	// 4. Load MiniFAT and Root MiniStream if needed
	var miniFat []int32
	var rootMiniStream []byte
	if rootEntry != nil && rootEntry.size > 0 && firstMiniFatSec >= 0 && numMiniFatSectors > 0 {
		mfBytes, err := readChain(firstMiniFatSec, int64(numMiniFatSectors*sectorSize))
		if err != nil {
			return nil, fmt.Errorf("reading CFB MiniFAT: %w", err)
		}
		miniFat = make([]int32, len(mfBytes)/4)
		for i := range miniFat {
			miniFat[i] = int32(binary.LittleEndian.Uint32(mfBytes[i*4 : (i+1)*4]))
		}
		rootMiniStream, err = readChain(rootEntry.startSec, rootEntry.size)
		if err != nil {
			return nil, fmt.Errorf("reading CFB Root MiniStream: %w", err)
		}
	}

	readStream := func(name string) ([]byte, error) {
		de, ok := streams[name]
		if !ok {
			return nil, fmt.Errorf("MSI stream %q not found", name)
		}
		if de.size == 0 {
			return nil, nil
		}
		if de.size < miniCutoff {
			var out bytes.Buffer
			msec := de.startSec
			maxHops := len(miniFat) + 1
			hops := 0
			for msec >= 0 && int64(out.Len()) < de.size {
				hops++
				if hops > maxHops || int(msec) >= len(miniFat) {
					return nil, fmt.Errorf("corrupt MiniFAT chain for %s", name)
				}
				startOff := int(msec) * miniSize
				if startOff >= len(rootMiniStream) {
					return nil, fmt.Errorf("MiniStream offset out of range for %s", name)
				}
				endOff := startOff + miniSize
				if endOff > len(rootMiniStream) {
					endOff = len(rootMiniStream)
				}
				chunk := rootMiniStream[startOff:endOff]
				rem := de.size - int64(out.Len())
				if rem < int64(len(chunk)) {
					chunk = chunk[:rem]
				}
				out.Write(chunk)
				msec = miniFat[msec]
			}
			return out.Bytes(), nil
		}
		return readChain(de.startSec, de.size)
	}

	sp, err := readStream("!_StringPool")
	if err != nil {
		return nil, err
	}
	sd, err := readStream("!_StringData")
	if err != nil {
		return nil, err
	}
	propBytes, err := readStream("!Property")
	if err != nil {
		return nil, err
	}
	if len(sp) < 4 {
		return nil, errors.New("corrupt MSI !_StringPool")
	}

	// Bit 0x80 of byte 3 indicates 3-byte string pool indices instead of 2-byte
	refSize := 2
	if sp[3]&0x80 != 0 {
		refSize = 3
	}

	pool := []string{""} // 1-based index
	sdOff := 0
	for p := 4; p+4 <= len(sp); p += 4 {
		strLen := int(binary.LittleEndian.Uint16(sp[p : p+2]))
		refCnt := binary.LittleEndian.Uint16(sp[p+2 : p+4])
		if strLen == 0 && refCnt > 0 {
			if p+8 > len(sp) {
				break
			}
			p += 4
			strLen = int(binary.LittleEndian.Uint32(sp[p : p+4]))
		}
		if strLen > 0 {
			if sdOff+strLen > len(sd) {
				strLen = len(sd) - sdOff
			}
			pool = append(pool, string(sd[sdOff:sdOff+strLen]))
			sdOff += strLen
		} else {
			pool = append(pool, "")
		}
	}

	rowStride := 2 * refSize
	if len(propBytes) == 0 || len(propBytes)%rowStride != 0 {
		return nil, errors.New("corrupt MSI !Property table")
	}
	numRows := len(propBytes) / rowStride

	readRef := func(offset int) int {
		if refSize == 2 {
			return int(binary.LittleEndian.Uint16(propBytes[offset : offset+2]))
		}
		return int(propBytes[offset]) | int(propBytes[offset+1])<<8 | int(propBytes[offset+2])<<16
	}

	props := make(map[string]string, numRows)
	for row := 0; row < numRows; row++ {
		kIdx := readRef(row * refSize)
		vIdx := readRef((numRows + row) * refSize)
		if kIdx > 0 && kIdx < len(pool) && vIdx > 0 && vIdx < len(pool) {
			props[pool[kIdx]] = pool[vIdx]
		}
	}

	prodCode, err := NormalizeProductCode(props["ProductCode"])
	if err != nil {
		return nil, fmt.Errorf("MSI missing valid ProductCode: %w", err)
	}

	meta := &Metadata{
		ProductCode:    prodCode,
		ProductName:    strings.TrimSpace(props["ProductName"]),
		ProductVersion: strings.TrimSpace(props["ProductVersion"]),
		Manufacturer:   strings.TrimSpace(props["Manufacturer"]),
		UpgradeCode:    strings.TrimSpace(props["UpgradeCode"]),
		FileSizeBytes:  totalSize,
	}
	if meta.ProductVersion == "" {
		meta.ProductVersion = "1.0.0"
	}
	return meta, nil
}

func decodeMSIStreamName(utf16Bytes []byte) string {
	chars := (len(utf16Bytes) / 2) - 1 // strip trailing UTF-16 NUL
	if chars <= 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < chars; i++ {
		ch := binary.LittleEndian.Uint16(utf16Bytes[i*2 : (i+1)*2])
		switch {
		case ch >= 0x3800 && ch < 0x4800:
			v := int(ch - 0x3800)
			b.WriteByte(msiNameAlphabet[v&0x3F])
			b.WriteByte(msiNameAlphabet[(v>>6)&0x3F])
		case ch >= 0x4800 && ch <= 0x4840:
			idx := int(ch - 0x4800)
			if idx < len(msiNameAlphabet) {
				b.WriteByte(msiNameAlphabet[idx])
			}
		default:
			b.WriteRune(rune(ch))
		}
	}
	return b.String()
}
