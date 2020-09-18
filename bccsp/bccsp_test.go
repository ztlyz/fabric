/*
Copyright IBM Corp. 2017 All Rights Reserved.

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

package bccsp

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSM4Opts(t *testing.T) {
	test := func(ephemeral bool) {
		for _, opts := range []KeyGenOpts{
			&GMSM4ImportKeyOpts{ephemeral},
		} {
			// fmt.Println("expect:", reflect.TypeOf(opts).String())
			// expectedAlgorithm := reflect.TypeOf(opts).String()[7:12]
			// require.Equal(t, expectedAlgorithm, opts.Algorithm())
			require.Equal(t, "GMSM4", opts.Algorithm())
			require.Equal(t, ephemeral, opts.Ephemeral())
		}
	}
	test(true)
	test(false)

	opts := &GMSM4KeyGenOpts{true}
	require.Equal(t, "GMSM4", opts.Algorithm())
	require.True(t, opts.Ephemeral())
	opts.Temporary = false
	require.False(t, opts.Ephemeral())
}

func TestSM2Opts(t *testing.T) {
	test := func(ephemeral bool) {
		for _, opts := range []KeyGenOpts{
			&GMSM2KeyGenOpts{ephemeral},
			// &ECDSAP384KeyGenOpts{ephemeral},
		} {
			// expectedAlgorithm := reflect.TypeOf(opts).String()[7:16]
			// require.Equal(t, expectedAlgorithm, opts.Algorithm())
			require.Equal(t, "GMSM2", opts.Algorithm())
			require.Equal(t, ephemeral, opts.Ephemeral())
		}
	}
	test(true)
	test(false)

	test = func(ephemeral bool) {
		for _, opts := range []KeyGenOpts{
			&GMSM2KeyGenOpts{ephemeral},
			&GMSM2PublicKeyImportOpts{ephemeral},
			&GMSM2PrivateKeyImportOpts{ephemeral},
			// &ECDSAGoPublicKeyImportOpts{ephemeral},
		} {
			require.Equal(t, "GMSM2", opts.Algorithm())
			require.Equal(t, ephemeral, opts.Ephemeral())
		}
	}
	test(true)
	test(false)

	// opts := &ECDSAReRandKeyOpts{Temporary: true}
	// require.True(t, opts.Ephemeral())
	// opts.Temporary = false
	// require.False(t, opts.Ephemeral())
	// require.Equal(t, "ECDSA_RERAND", opts.Algorithm())
	// require.Empty(t, opts.ExpansionValue())
}

func TestAESOpts(t *testing.T) {
	test := func(ephemeral bool) {
		for _, opts := range []KeyGenOpts{
			&AES128KeyGenOpts{ephemeral},
			&AES192KeyGenOpts{ephemeral},
			&AES256KeyGenOpts{ephemeral},
		} {
			expectedAlgorithm := reflect.TypeOf(opts).String()[7:13]
			require.Equal(t, expectedAlgorithm, opts.Algorithm())
			require.Equal(t, ephemeral, opts.Ephemeral())
		}
	}
	test(true)
	test(false)

	opts := &AESKeyGenOpts{true}
	require.Equal(t, "AES", opts.Algorithm())
	require.True(t, opts.Ephemeral())
	opts.Temporary = false
	require.False(t, opts.Ephemeral())
}

func TestECDSAOpts(t *testing.T) {
	test := func(ephemeral bool) {
		for _, opts := range []KeyGenOpts{
			&ECDSAP256KeyGenOpts{ephemeral},
			&ECDSAP384KeyGenOpts{ephemeral},
		} {
			expectedAlgorithm := reflect.TypeOf(opts).String()[7:16]
			require.Equal(t, expectedAlgorithm, opts.Algorithm())
			require.Equal(t, ephemeral, opts.Ephemeral())
		}
	}
	test(true)
	test(false)

	test = func(ephemeral bool) {
		for _, opts := range []KeyGenOpts{
			&ECDSAKeyGenOpts{ephemeral},
			&ECDSAPKIXPublicKeyImportOpts{ephemeral},
			&ECDSAPrivateKeyImportOpts{ephemeral},
			&ECDSAGoPublicKeyImportOpts{ephemeral},
		} {
			require.Equal(t, "ECDSA", opts.Algorithm())
			require.Equal(t, ephemeral, opts.Ephemeral())
		}
	}
	test(true)
	test(false)

	opts := &ECDSAReRandKeyOpts{Temporary: true}
	require.True(t, opts.Ephemeral())
	opts.Temporary = false
	require.False(t, opts.Ephemeral())
	require.Equal(t, "ECDSA_RERAND", opts.Algorithm())
	require.Empty(t, opts.ExpansionValue())
}

func TestHashOpts(t *testing.T) {
	for _, ho := range []HashOpts{&SHA256Opts{}, &SHA384Opts{}, &SHA3_256Opts{}, &SHA3_384Opts{}} {
		s := strings.Replace(reflect.TypeOf(ho).String(), "*bccsp.", "", -1)
		algorithm := strings.Replace(s, "Opts", "", -1)
		require.Equal(t, algorithm, ho.Algorithm())
		ho2, err := GetHashOpt(algorithm)
		require.NoError(t, err)
		require.Equal(t, ho.Algorithm(), ho2.Algorithm())
	}
	_, err := GetHashOpt("foo")
	require.Error(t, err)
	require.Contains(t, err.Error(), "hash function not recognized")

	require.Equal(t, "SHA", (&SHAOpts{}).Algorithm())
}

func TestHMAC(t *testing.T) {
	opts := &HMACTruncated256AESDeriveKeyOpts{Arg: []byte("arg")}
	require.False(t, opts.Ephemeral())
	opts.Temporary = true
	require.True(t, opts.Ephemeral())
	require.Equal(t, "HMAC_TRUNCATED_256", opts.Algorithm())
	require.Equal(t, []byte("arg"), opts.Argument())

	opts2 := &HMACDeriveKeyOpts{Arg: []byte("arg")}
	require.False(t, opts2.Ephemeral())
	opts2.Temporary = true
	require.True(t, opts2.Ephemeral())
	require.Equal(t, "HMAC", opts2.Algorithm())
	require.Equal(t, []byte("arg"), opts2.Argument())
}

func TestKeyGenOpts(t *testing.T) {
	expectedAlgorithms := map[reflect.Type]string{
		// reflect.TypeOf(&HMACImportKeyOpts{}):       "HMAC",
		// reflect.TypeOf(&X509PublicKeyImportOpts{}): "X509Certificate",
		// reflect.TypeOf(&AES256ImportKeyOpts{}):     "AES",
		reflect.TypeOf(&GMSM4ImportKeyOpts{}): "GMSM4",
	}
	test := func(ephemeral bool) {
		for _, opts := range []KeyGenOpts{
			// &HMACImportKeyOpts{ephemeral},
			// &X509PublicKeyImportOpts{ephemeral},
			// &AES256ImportKeyOpts{ephemeral},
			&GMSM4ImportKeyOpts{ephemeral},
		} {
			expectedAlgorithm := expectedAlgorithms[reflect.TypeOf(opts)]
			require.Equal(t, expectedAlgorithm, opts.Algorithm())
			require.Equal(t, ephemeral, opts.Ephemeral())
		}
	}
	test(true)
	test(false)
}
