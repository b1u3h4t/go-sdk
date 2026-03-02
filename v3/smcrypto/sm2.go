package smcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math/big"

	"github.com/FISCO-BCOS/crypto/ecdsa"
	"github.com/FISCO-BCOS/crypto/elliptic"
	"github.com/FISCO-BCOS/go-sdk/v3/smcrypto/sm3"
)

const defaultSM2ID = "1234567812345678"
const sm2FieldBytes = 32

func bigIntTo32Bytes(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) > sm2FieldBytes {
		b = b[len(b)-sm2FieldBytes:]
	}
	out := make([]byte, sm2FieldBytes)
	copy(out[sm2FieldBytes-len(b):], b)
	return out
}

// SM2PreProcess compute z value of id and return z||m. Pads a,b,Gx,Gy,X,Y to 32 bytes big-endian to match OpenSSL sm2_compute_z_digest and bcos-crypto WITH_SM2_OPTIMIZE (GM/T 0003).
func SM2PreProcess(src []byte, id string, priv *ecdsa.PrivateKey) ([]byte, error) {
	params := elliptic.Sm2p256v1().Params()
	length := uint16(len(id) * 8)
	var data []byte
	buf := bytes.NewBuffer(data)
	err := binary.Write(buf, binary.BigEndian, length)
	if err != nil {
		return nil, err
	}
	_, err = buf.Write([]byte(id))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(bigIntTo32Bytes(params.A))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(bigIntTo32Bytes(params.B))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(bigIntTo32Bytes(params.Gx))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(bigIntTo32Bytes(params.Gy))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(bigIntTo32Bytes(priv.X))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(bigIntTo32Bytes(priv.Y))
	if err != nil {
		return nil, err
	}
	z := sm3.Hash(buf.Bytes())
	// fmt.Printf("digest sm3 hash :%x\n", z)
	return append(z, src...), nil
}

// SM2Sign return sm2 signature
func SM2Sign(src []byte, priv *ecdsa.PrivateKey) (r, s *big.Int, err error) {
	data, err := SM2PreProcess(src, defaultSM2ID, priv)
	if err != nil {
		return nil, nil, err
	}
	e := sm3.Hash(data)
	// fmt.Printf("message sm3 hash :%x\n", e)
	eInt := new(big.Int).SetBytes(e)
	n := elliptic.Sm2p256v1().Params().N
	d := priv.D

	for {
		k, x, _, err := elliptic.GenerateKey(elliptic.Sm2p256v1(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		kInt := new(big.Int).SetBytes(k)

		if big.NewInt(0).Cmp(kInt) == 0 {
			continue
		}
		r = new(big.Int).Add(eInt, x)
		r.Mod(r, n)
		if new(big.Int).Add(r, kInt).Cmp(n) == 0 {
			continue
		}
		if big.NewInt(0).Cmp(r) == 0 {
			continue
		}

		tmp := new(big.Int).Add(d, big.NewInt(1))
		tmp.Exp(tmp, new(big.Int).Sub(n, big.NewInt(2)), n)
		s = new(big.Int).Mul(r, d)
		s.Sub(kInt, s)
		s.Mul(s, tmp)
		s.Mod(s, n)
		if big.NewInt(0).Cmp(s) == 0 {
			continue
		}
		return r, s, err
	}
}
