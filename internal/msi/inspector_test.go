package msi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// encodeMSIStreamName encodes an MSI table stream name (e.g. "!Property",
// "!_StringPool", "!_StringData") using the MSI 0x4800 single-char alphabet so
// unit tests can build synthetic CFB .msi files in memory.
func encodeMSIStreamName(name string) []byte {
	if name == "Root Entry" {
		out := make([]byte, (len(name)+1)*2)
		for i, r := range name {
			binary.LittleEndian.PutUint16(out[i*2:], uint16(r))
		}
		return out
	}
	out := make([]byte, (len(name)+1)*2)
	for i := 0; i < len(name); i++ {
		idx := strings.IndexByte(msiNameAlphabet, name[i])
		if idx >= 0 {
			binary.LittleEndian.PutUint16(out[i*2:], uint16(0x4800+idx))
		} else {
			binary.LittleEndian.PutUint16(out[i*2:], uint16(name[i]))
		}
	}
	return out
}

// buildTestMSI constructs a minimal valid CFB v3 (512-byte sector) MSI binary
// containing !_StringPool, !_StringData, and !Property streams.
func buildTestMSI(props [][2]string) []byte {
	const sectorSize = 512

	// Build !_StringPool + !_StringData
	var sp bytes.Buffer
	var sd bytes.Buffer
	sp.Write([]byte{0xE4, 0x04, 0x00, 0x00}) // codepage 1252, 2-byte refs

	var propKeys, propVals []uint16
	nextIdx := uint16(1)
	addStr := func(s string) uint16 {
		var entry [4]byte
		binary.LittleEndian.PutUint16(entry[0:2], uint16(len(s)))
		binary.LittleEndian.PutUint16(entry[2:4], 1)
		sp.Write(entry[:])
		sd.WriteString(s)
		idx := nextIdx
		nextIdx++
		return idx
	}
	for _, kv := range props {
		propKeys = append(propKeys, addStr(kv[0]))
		propVals = append(propVals, addStr(kv[1]))
	}

	// Column-major !Property stream
	var propBuf bytes.Buffer
	for _, k := range propKeys {
		_ = binary.Write(&propBuf, binary.LittleEndian, k)
	}
	for _, v := range propVals {
		_ = binary.Write(&propBuf, binary.LittleEndian, v)
	}

	// Place all 3 streams in FAT sectors (miniCutoff = 0 so every stream uses FAT directly):
	// Sector 0: FAT
	// Sector 1: Directory
	// Sector 2: !_StringPool
	// Sector 3: !_StringData
	// Sector 4: !Property
	padSector := func(b []byte) []byte {
		out := make([]byte, sectorSize)
		copy(out, b)
		return out
	}

	fat := make([]byte, sectorSize)
	for i := 0; i < sectorSize; i += 4 {
		binary.LittleEndian.PutUint32(fat[i:], 0xFFFFFFFF)
	}
	endChain := uint32(0xFFFFFFFE)
	binary.LittleEndian.PutUint32(fat[0*4:], 0xFFFFFFFD) // FATSECT
	binary.LittleEndian.PutUint32(fat[1*4:], endChain)   // Dir
	binary.LittleEndian.PutUint32(fat[2*4:], endChain)   // !_StringPool
	binary.LittleEndian.PutUint32(fat[3*4:], endChain)   // !_StringData
	binary.LittleEndian.PutUint32(fat[4*4:], endChain)   // !Property

	dir := make([]byte, sectorSize)
	writeDir := func(slot int, name string, objType byte, startSec uint32, size uint32) {
		off := slot * 128
		enc := encodeMSIStreamName(name)
		copy(dir[off:], enc)
		binary.LittleEndian.PutUint16(dir[off+64:], uint16(len(enc)))
		dir[off+66] = objType
		dir[off+67] = 1
		binary.LittleEndian.PutUint32(dir[off+68:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(dir[off+72:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(dir[off+76:], 1)
		binary.LittleEndian.PutUint32(dir[off+116:], startSec)
		binary.LittleEndian.PutUint32(dir[off+120:], size)
	}
	writeDir(0, "Root Entry", 5, 0xFFFFFFFE, 0)
	writeDir(1, "!_StringPool", 2, 2, uint32(sp.Len()))
	writeDir(2, "!_StringData", 2, 3, uint32(sd.Len()))
	writeDir(3, "!Property", 2, 4, uint32(propBuf.Len()))

	hdr := make([]byte, sectorSize)
	copy(hdr[:8], cfbMagic)
	binary.LittleEndian.PutUint16(hdr[24:], 0x003E)     // minor version
	binary.LittleEndian.PutUint16(hdr[26:], 0x0003)     // v3
	binary.LittleEndian.PutUint16(hdr[28:], 0xFFFE)     // little-endian
	binary.LittleEndian.PutUint16(hdr[30:], 9)          // 512-byte sectors
	binary.LittleEndian.PutUint16(hdr[32:], 6)          // 64-byte mini-sectors
	binary.LittleEndian.PutUint32(hdr[44:], 1)          // 1 FAT sector
	binary.LittleEndian.PutUint32(hdr[48:], 1)          // Dir starts at sector 1
	binary.LittleEndian.PutUint32(hdr[56:], 0)          // miniCutoff = 0
	binary.LittleEndian.PutUint32(hdr[60:], 0xFFFFFFFE) // no MiniFAT
	binary.LittleEndian.PutUint32(hdr[68:], 0xFFFFFFFE) // no extra DIFAT
	binary.LittleEndian.PutUint32(hdr[76:], 0)          // DIFAT[0] = sector 0
	for i := 1; i < 109; i++ {
		binary.LittleEndian.PutUint32(hdr[76+i*4:], 0xFFFFFFFF)
	}

	var file bytes.Buffer
	file.Write(hdr)
	file.Write(fat)
	file.Write(dir)
	file.Write(padSector(sp.Bytes()))
	file.Write(padSector(sd.Bytes()))
	file.Write(padSector(propBuf.Bytes()))
	return file.Bytes()
}

func TestInspectReaderAt_AndStreamDownload(t *testing.T) {
	rawMSI := buildTestMSI([][2]string{
		{"ProductCode", "{b3db5e18-7fda-3432-9931-2e60d41bd242}"},
		{"ProductName", "Google Chrome"},
		{"ProductVersion", "157.0.8103.79"},
		{"Manufacturer", "Google LLC"},
		{"UpgradeCode", "{C1DFDF69-5945-32F2-A35E-EE94C99C7CF4}"},
	})

	meta, err := InspectReaderAt(bytes.NewReader(rawMSI), int64(len(rawMSI)))
	if err != nil {
		t.Fatalf("InspectReaderAt failed: %v", err)
	}
	if meta.ProductCode != "{B3DB5E18-7FDA-3432-9931-2E60D41BD242}" {
		t.Fatalf("ProductCode = %q", meta.ProductCode)
	}
	if meta.ProductName != "Google Chrome" || meta.ProductVersion != "157.0.8103.79" || meta.Manufacturer != "Google LLC" {
		t.Fatalf("unexpected metadata: %+v", meta)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(rawMSI)
	}))
	defer srv.Close()

	dlMeta, err := inspectURLWithClient(context.Background(), srv.URL+"/chrome.msi", srv.Client())
	if err != nil {
		t.Fatalf("inspectURLWithClient failed: %v", err)
	}
	sum := sha256.Sum256(rawMSI)
	wantHash := strings.ToUpper(hex.EncodeToString(sum[:]))
	if dlMeta.SHA256 != wantHash || dlMeta.FileSizeBytes != int64(len(rawMSI)) {
		t.Fatalf("SHA256/size mismatch: got (%s, %d), want (%s, %d)", dlMeta.SHA256, dlMeta.FileSizeBytes, wantHash, len(rawMSI))
	}
}

func TestValidateContentURL_BlocksSSRF(t *testing.T) {
	if err := ValidateContentURL("https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"); err != nil {
		t.Fatalf("expected Google Chrome URL to pass, got: %v", err)
	}
	for _, bad := range []string{
		"http://dl.google.com/app.msi",
		"https://127.0.0.1/app.msi",
		"https://169.254.169.254/latest/meta-data",
		"https://10.0.0.5/internal.msi",
		"https://user:secret@dl.google.com/app.msi",
	} {
		if err := ValidateContentURL(bad); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
}
