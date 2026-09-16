package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/camalolo/freens/internal/constants"
)

func TestKeypair(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.Public()) != 32 {
		t.Errorf("public len = %d, want 32", len(kp.Public()))
	}
	if len(kp.Seed()) != 32 {
		t.Errorf("seed len = %d, want 32", len(kp.Seed()))
	}
	sig := kp.Sign([]byte("msg"))
	if len(sig) != 64 {
		t.Errorf("sig len = %d, want 64", len(sig))
	}
	// Deterministic from seed.
	kp1, _ := FromSeed(bytes.Repeat([]byte{0x11}, 32))
	kp2, _ := FromSeed(bytes.Repeat([]byte{0x11}, 32))
	if !bytes.Equal(kp1.Public(), kp2.Public()) {
		t.Error("FromSeed not deterministic (public)")
	}
	if !bytes.Equal(kp1.Sign([]byte("x")), kp2.Sign([]byte("x"))) {
		t.Error("FromSeed not deterministic (sign)")
	}
	if _, err := FromSeed(bytes.Repeat([]byte{0x11}, 31)); err == nil {
		t.Error("FromSeed should reject 31-byte seed")
	}
}

func TestVerify(t *testing.T) {
	kp, _ := Generate()
	msg := []byte("hello world")
	sig := kp.Sign(msg)
	if !Verify(kp.Public(), sig, msg) {
		t.Error("Verify valid sig failed")
	}
	if Verify(kp.Public(), sig, []byte("tampered")) {
		t.Error("Verify tampered msg should fail")
	}
	if Verify(bytes.Repeat([]byte{0}, 32), sig, msg) {
		t.Error("Verify wrong key should fail")
	}
	if Verify(kp.Public(), bytes.Repeat([]byte{0}, 64), msg) {
		t.Error("Verify bad sig should fail")
	}
	if Verify(kp.Public(), bytes.Repeat([]byte{0}, 32), msg) {
		t.Error("Verify wrong sig len should fail")
	}
	// matches stdlib directly
	if !ed25519.Verify(kp.Public(), msg, sig) {
		t.Error("stdlib Verify disagrees")
	}
}

func TestTldID(t *testing.T) {
	kp, _ := Generate()
	id, err := TldID(kp.Public())
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(kp.Public())
	if !bytes.Equal(id, want[:]) {
		t.Error("TldID != SHA-256(pk)")
	}
	nid, _ := NodeID(kp.Public())
	if !bytes.Equal(nid, id) {
		t.Error("NodeID != TldID")
	}
	// distinct keys -> distinct ids
	kp2, _ := Generate()
	id2, _ := TldID(kp2.Public())
	if bytes.Equal(id, id2) {
		t.Error("distinct keys produced same id")
	}
	if _, err := TldID(bytes.Repeat([]byte{0}, 31)); err == nil {
		t.Error("TldID should reject 31-byte key")
	}
}

// TestKeypairAccessorsReturnCopies: Public() and Seed() must hand out COPIES
// of the key material — the private key buffer holds seed||public in one
// allocation, so an aliased return value let any caller write corrupt the
// keypair (either half).
func TestKeypairAccessorsReturnCopies(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub := kp.Public()
	seed := kp.Seed()
	pub[0] ^= 0xff
	seed[31] ^= 0xff
	if bytes.Equal(kp.Public(), pub) {
		t.Error("mutating the returned public slice affected the keypair")
	}
	if bytes.Equal(kp.Seed(), seed) {
		t.Error("mutating the returned seed slice affected the keypair")
	}
	// And repeated calls are stable (fresh copies each time, same values).
	if !bytes.Equal(kp.Public(), kp.Public()) {
		t.Error("Public() not stable across calls")
	}
	if !bytes.Equal(kp.Seed(), kp.Seed()) {
		t.Error("Seed() not stable across calls")
	}
	// The keypair still signs validly after the attempted corruption.
	msg := []byte("still intact")
	if !Verify(kp.Public(), kp.Sign(msg), msg) {
		t.Error("keypair corrupted through an accessor-returned slice")
	}
}

func TestLeadingZeroBits(t *testing.T) {
	cases := []struct {
		hex_ string
		want int
	}{
		{"ff", 0},
		{"7f", 1},
		{"40", 1},
		{"01", 7},
		{"10", 3},
		{"00", 8},
		{"0001", 15},
		{"0010", 11},
	}
	for _, c := range cases {
		b := []byte{}
		for i := 0; i < len(c.hex_); i += 2 {
			b = append(b, fromHex2(c.hex_[i:i+2]))
		}
		if got := LeadingZeroBits(b); got != c.want {
			t.Errorf("LeadingZeroBits(%s) = %d, want %d", c.hex_, got, c.want)
		}
	}
	// 32 zero bytes -> 256
	if got := LeadingZeroBits(bytes.Repeat([]byte{0}, 32)); got != 256 {
		t.Errorf("32 zeros = %d, want 256", got)
	}
	// empty -> 0
	if got := LeadingZeroBits(nil); got != 0 {
		t.Errorf("empty = %d, want 0", got)
	}
}

func fromHex2(s string) byte {
	var v byte
	for i := 0; i < 2; i++ {
		c := s[i]
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= c - '0'
		case c >= 'a' && c <= 'f':
			v |= c - 'a' + 10
		}
	}
	return v
}

func TestMeetsDifficulty(t *testing.T) {
	if !MeetsDifficulty([]byte{0x00}, 8) {
		t.Error("0x00 should meet difficulty 8")
	}
	if MeetsDifficulty([]byte{0x00}, 9) {
		t.Error("0x00 should not meet difficulty 9")
	}
	if !MeetsDifficulty([]byte{0x7f}, 1) {
		t.Error("0x7f should meet difficulty 1")
	}
	if MeetsDifficulty([]byte{0x7f}, 2) {
		t.Error("0x7f should not meet difficulty 2")
	}
}

func TestClampDifficultyByte(t *testing.T) {
	// Locks the Appendix A.4 difficulty-byte clamp: nonce[0] = min(d, 255).
	// This matches the Python reference (crypto.py:248); the Go bug was that
	// difficulty > 255 produced nonce[0]=0 instead of 255. Difficulty > 255 is
	// not mineable in practice (v1 init is 24), so we test the helper directly.
	cases := []struct {
		in, want int
	}{
		{0, 0},
		{8, 8},
		{24, 24},   // v1 init difficulty
		{254, 254}, // boundary just below cap
		{255, 255}, // exact cap
		{256, 255}, // first clamp
		{1000, 255},
	}
	for _, c := range cases {
		if got := int(clampDifficultyByte(c.in)); got != c.want {
			t.Errorf("clampDifficultyByte(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestMinePoW(t *testing.T) {
	// Low difficulty for speed.
	prefix := []byte("test-prefix")
	nonce, h, err := MinePoW(prefix, 8, 2_000_000, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 16 {
		t.Fatalf("nonce len = %d, want 16", len(nonce))
	}
	if nonce[0] != 8 {
		t.Errorf("nonce[0] = %d, want 8 (difficulty)", nonce[0])
	}
	if !bytes.Equal(PoWHash(prefix, nonce), h) {
		t.Error("returned hash != recomputed PoWHash")
	}
	if !MeetsDifficulty(h, 8) {
		t.Error("mined hash does not meet difficulty 8")
	}
	if !MeetsDifficulty(PoWHash(prefix, nonce), 8) {
		t.Error("recomputed hash does not meet difficulty 8")
	}
	// difficulty 0 always succeeds immediately
	n0, _, err := MinePoW([]byte("x"), 0, 10, 8)
	if err != nil {
		t.Fatal(err)
	}
	if n0[0] != 0 {
		t.Errorf("difficulty-0 nonce[0] = %d, want 0", n0[0])
	}
	// impossible difficulty -> never verifies
	if MeetsDifficulty(PoWHash(prefix, nonce), 256) {
		t.Error("difficulty 256 should be impossible")
	}
	// PoWHash determinism
	wantSha := sha256.Sum256([]byte("ab"))
	if !bytes.Equal(PoWHash([]byte("a"), []byte("b")), wantSha[:]) {
		t.Error("PoWHash(a,b) != SHA-256(ab)")
	}
}

// BenchmarkMinePoW measures the mining hot loop at a small difficulty so
// the iteration count dominates (the production shape is ~16.7 M iterations
// per registration): the per-iteration cost is one crypto/rand fill plus
// one SHA-256 over prefix||nonce.
func BenchmarkMinePoW(b *testing.B) {
	prefix := bytes.Repeat([]byte{0x5a}, 64)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := MinePoW(prefix, 0, 10000, 16); err != nil {
			b.Fatal(err)
		}
	}
}

// TestMinePoWZeroNonceSize: the degenerate "hash the prefix only" nonce
// space must not panic the reuse-buffer loop — difficulty 0 succeeds on the
// first attempt with an empty nonce, any real difficulty exhausts.
func TestMinePoWZeroNonceSize(t *testing.T) {
	n, h, err := MinePoW([]byte("prefix"), 0, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(n) != 0 {
		t.Fatalf("nonce len = %d, want 0", len(n))
	}
	if !bytes.Equal(PoWHash([]byte("prefix"), nil), h) {
		t.Error("hash mismatch for empty nonce")
	}
	if _, _, err := MinePoW([]byte("p"), 8, 10, 0); err == nil {
		t.Error("difficulty 8 with an empty nonce space must exhaust")
	}
}

func TestWitnessSigningMessage(t *testing.T) {
	ph := bytes.Repeat([]byte{1}, 32) // a claim prefix hash
	msg, err := WitnessSigningMessage(ph, 12345)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(msg, WitnessSigningTag) {
		t.Error("missing tag prefix")
	}
	want := append([]byte{}, WitnessSigningTag...)
	want = append(want, ph...)
	// uint64_be(12345) = 0x0000000000003039
	want = append(want, 0, 0, 0, 0, 0, 0, 0x30, 0x39)
	if !bytes.Equal(msg, want) {
		t.Errorf("msg = %x, want %x", msg, want)
	}
	if _, err := WitnessSigningMessage(ph[:31], 1); err == nil {
		t.Error("should reject 31-byte prefix hash")
	}
}

// reference constants to satisfy the importer in case constants isn't otherwise used.
var _ = constants.ProtoVersion
