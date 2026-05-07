package crypto

import (
	"errors"

	"github.com/cloudflare/circl/group"
)

var (
	ErrInvalidProof       = errors.New("invalid ZKP proof")
	ErrInvalidPublicKey   = errors.New("invalid public key encoding")
	ErrInvalidChallenge   = errors.New("invalid challenge encoding")
	ErrInvalidProofPoint  = errors.New("invalid proof point encoding")
	ErrInvalidProofScalar = errors.New("invalid proof scalar encoding")
)

// VerifySchnorr verifies a Schnorr zero-knowledge proof.
//
// Given:
//   - publicKey: Y = x * G (32 bytes, compressed Ristretto)
//   - challenge: C (32 bytes, scalar)
//   - proofT: T = r * G (32 bytes, compressed Ristretto point)
//   - proofS: s = r + C * x (mod q) (32 bytes, scalar)
//
// Verifies: s * G == T + C * Y
func VerifySchnorr(publicKey, challenge, proofT, proofS []byte) error {
	g := group.Ristretto255
	params := g.Params()

	if uint(len(publicKey)) != params.CompressedElementLength {
		return ErrInvalidPublicKey
	}
	if uint(len(challenge)) != params.ScalarLength {
		return ErrInvalidChallenge
	}
	if uint(len(proofT)) != params.CompressedElementLength {
		return ErrInvalidProofPoint
	}
	if uint(len(proofS)) != params.ScalarLength {
		return ErrInvalidProofScalar
	}

	// Decode Y
	y := g.NewElement()
	if err := y.UnmarshalBinary(publicKey); err != nil {
		return ErrInvalidPublicKey
	}

	// Decode C
	c := g.NewScalar()
	if err := c.UnmarshalBinary(challenge); err != nil {
		return ErrInvalidChallenge
	}

	// Decode T
	t := g.NewElement()
	if err := t.UnmarshalBinary(proofT); err != nil {
		return ErrInvalidProofPoint
	}

	// Decode s
	s := g.NewScalar()
	if err := s.UnmarshalBinary(proofS); err != nil {
		return ErrInvalidProofScalar
	}

	// lhs = s * G
	lhs := g.NewElement().MulGen(s)

	// rhs = T + C * Y
	cY := g.NewElement().Mul(y, c)
	rhs := g.NewElement().Add(t, cY)

	if !lhs.IsEqual(rhs) {
		return ErrInvalidProof
	}

	return nil
}
