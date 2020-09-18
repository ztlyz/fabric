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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGMSM4EncryptorDecrypt tests the integration of
// gmsm4Encryptor and gmsm4Decryptor
func TestGMSM4EncryptorDecrypt(t *testing.T) {
	t.Parallel()

	raw, err := GetRandomBytes(32)
	// fmt.Println("raw:", raw)
	require.NoError(t, err)
	fmt.Println("raw:", raw)

	k := &gmsm4PrivateKey{privKey: raw, exportable: false}
	fmt.Println("k:", k)

	//补齐到16位
	msg := []byte("Hello World !!!!")
	encryptor := &gmsm4Encryptor{}

	ct, err := encryptor.Encrypt(k, msg, nil)
	require.NoError(t, err)

	decryptor := &gmsm4Decryptor{}

	msg2, err := decryptor.Decrypt(k, ct, nil)
	require.NoError(t, err)
	require.Equal(t, msg, msg2)
}
