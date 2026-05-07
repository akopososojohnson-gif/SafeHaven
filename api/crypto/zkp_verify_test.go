package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/group"
)

func generateProof() (publicKey, challenge, proofT, proofS []byte, err error) {
	g := group.Ristretto255

	// Generate keypair: x, Y = x*G
	x := g.RandomScalar(rand.Reader)
	y := g.NewElement().MulGen(x)

	// Generate random challenge C
	c := g.RandomScalar(rand.Reader)

	// Prover: random r, T = r*G, s = r + C*x
	r := g.RandomScalar(rand.Reader)
	t := g.NewElement().MulGen(r)

	// s = r + C*x
	cx := g.NewScalar().Mul(c, x)
	s := g.NewScalar().Add(r, cx)

	publicKey, _ = y.MarshalBinaryCompress()
	challenge, _ = c.MarshalBinary()
	proofT, _ = t.MarshalBinaryCompress()
	proofS, _ = s.MarshalBinary()

	return publicKey, challenge, proofT, proofS, nil
}

func TestVerifySchnorrValid(t *testing.T) {
	pk, ch, pt, ps, err := generateProof()
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	if err := VerifySchnorr(pk, ch, pt, ps); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
}

func TestVerifySchnorrWrongChallenge(t *testing.T) {
	pk, _, pt, ps, err := generateProof()
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	g := group.Ristretto255
	wrongC := g.RandomScalar(rand.Reader)
	wrongCBytes, _ := wrongC.MarshalBinary()

	if err := VerifySchnorr(pk, wrongCBytes, pt, ps); err == nil {
		t.Fatal("expected error for wrong challenge")
	}
}

func TestVerifySchnorrWrongPublicKey(t *testing.T) {
	_, ch, pt, ps, err := generateProof()
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	g := group.Ristretto255
	wrongY := g.NewElement().MulGen(g.RandomScalar(rand.Reader))
	wrongPK, _ := wrongY.MarshalBinaryCompress()

	if err := VerifySchnorr(wrongPK, ch, pt, ps); err == nil {
		t.Fatal("expected error for wrong public key")
	}
}

func TestVerifySchnorrInvalidLengths(t *testing.T) {
	pk := make([]byte, 32)
	ch := make([]byte, 32)
	pt := make([]byte, 32)
	ps := make([]byte, 32)

	if err := VerifySchnorr([]byte{1, 2, 3}, ch, pt, ps); err != ErrInvalidPublicKey {
		t.Fatalf("expected ErrInvalidPublicKey, got %v", err)
	}
	if err := VerifySchnorr(pk, []byte{1, 2, 3}, pt, ps); err != ErrInvalidChallenge {
		t.Fatalf("expected ErrInvalidChallenge, got %v", err)
	}
	if err := VerifySchnorr(pk, ch, []byte{1, 2, 3}, ps); err != ErrInvalidProofPoint {
		t.Fatalf("expected ErrInvalidProofPoint, got %v", err)
	}
	if err := VerifySchnorr(pk, ch, pt, []byte{1, 2, 3}); err != ErrInvalidProofScalar {
		t.Fatalf("expected ErrInvalidProofScalar, got %v", err)
	}
}
