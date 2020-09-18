/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package gm

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tjfoc/gmsm/sm2"
)

func TestVerifyGMSM2(t *testing.T) {
	t.Parallel()

	// Generate a key
	lowLevelKey, err := sm2.GenerateKey()
	require.NoError(t, err)

	msg := []byte("hello world")
	sigma, err := signGMSM2(lowLevelKey, msg, nil)
	require.NoError(t, err)

	_, err = verifyGMSM2(&lowLevelKey.PublicKey, nil, msg, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Failed")

	valid, err := verifyGMSM2(&lowLevelKey.PublicKey, sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestGMSM2SignerSign(t *testing.T) {
	t.Parallel()

	signer := &gmsm2Signer{}
	verifierPrivateKey := &gmsm2PrivateKeyVerifier{}
	verifierPublicKey := &gmsm2PublicKeyVerifier{}

	// Generate a key
	lowLevelKey, err := sm2.GenerateKey()
	require.NoError(t, err)
	k := &gmsm2PrivateKey{lowLevelKey}
	pk, err := k.PublicKey()
	require.NoError(t, err)

	// Sign
	msg := []byte("Hello World")
	sigma, err := signer.Sign(k, msg, nil)
	fmt.Println("sigma:", sigma, err)
	require.NoError(t, err)
	require.NotNil(t, sigma)

	// Verify
	valid, err := verifyGMSM2(&lowLevelKey.PublicKey, sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)

	valid, err = verifierPrivateKey.Verify(k, sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)

	valid, err = verifierPublicKey.Verify(pk, sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)
	// require.Fail(t, "valid")
}

func TestGMSM2PrivateKey(t *testing.T) {
	t.Parallel()

	lowLevelKey, err := sm2.GenerateKey()
	fmt.Println("lowLevelKey:", lowLevelKey)
	require.NoError(t, err)
	k := &gmsm2PrivateKey{lowLevelKey}
	fmt.Println("k:", k)

	require.False(t, k.Symmetric())
	require.True(t, k.Private())

	_, err = k.Bytes()
	require.Error(t, err)
	require.Contains(t, err.Error(), "Not supported.")

	k.privKey = nil
	ski := k.SKI()
	require.Nil(t, ski)

	k.privKey = lowLevelKey
	ski = k.SKI()
	require.NotNil(t, ski)

	// raw := elliptic.Marshal(k.privKey.Curve, k.privKey.PublicKey.X, k.privKey.PublicKey.Y)
	// hash := sha256.New()
	// hash.Write(raw)
	// ski2 := hash.Sum(nil)
	// require.Equal(t, ski2, ski, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	require.NoError(t, err)
	require.NotNil(t, pk)
	gmsm2PK, ok := pk.(*gmsm2PublicKey)
	require.True(t, ok)
	require.Equal(t, &lowLevelKey.PublicKey, gmsm2PK.pubKey)
}

func TestGMSM2PublicKey(t *testing.T) {
	t.Parallel()

	lowLevelKey, err := sm2.GenerateKey()
	require.NoError(t, err)
	k := &gmsm2PublicKey{&lowLevelKey.PublicKey}

	require.False(t, k.Symmetric())
	require.False(t, k.Private())

	k.pubKey = nil
	ski := k.SKI()
	require.Nil(t, ski)

	k.pubKey = &lowLevelKey.PublicKey
	ski = k.SKI()
	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	require.Equal(t, ski, ski2, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	require.NoError(t, err)
	require.Equal(t, k, pk)

	bytes, err := k.Bytes()
	require.NoError(t, err)
	bytes2, err := sm2.MarshalSm2PublicKey(k.pubKey)
	require.NoError(t, err)
	require.Equal(t, bytes2, bytes, "bytes are not computed in the right way.")

	// invalidCurve := &elliptic.CurveParams{Name: "P-Invalid"}
	// invalidCurve.BitSize = 1024
	// k.pubKey = &sm2.PublicKey{Curve: invalidCurve, X: big.NewInt(1), Y: big.NewInt(1)}
	// _, err = k.Bytes()
	// require.Error(t, err)
	// require.Contains(t, err.Error(), "Failed marshalling key [")
}
