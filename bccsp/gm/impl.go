/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.

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
	// "crypto/sha256"
	// "crypto/sha512"
	"hash"
	"reflect"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/pkg/errors"
	// "github.com/tjfoc/gmsm/sm3"
	// "golang.org/x/crypto/sha3"
)

var (
	logger = flogging.MustGetLogger("bccsp_gm")
)

// // NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// // at security level 256, hash family SHA2 and using FolderBasedKeyStore as KeyStore.
// func NewDefaultSecurityLevel(keyStorePath string) (bccsp.BCCSP, error) {
// 	ks := &fileBasedKeyStore{}
// 	if err := ks.Init(nil, keyStorePath, false); err != nil {
// 		return nil, errors.Wrapf(err, "Failed initializing key store at [%v]", keyStorePath)
// 	}

// 	return New(256, "SHA2", ks)
// }

// // NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// // at security level 256, hash family SHA2 and using the passed KeyStore.
// func NewDefaultSecurityLevelWithKeystore(keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
// 	return New(256, "SHA2", keyStore)
// }

// CSP provides a generic implementation of the BCCSP interface based
// on wrappers. It can be customized by providing implementations for the
// following algorithm-based wrappers: KeyGenerator, KeyDeriver, KeyImporter,
// Encryptor, Decryptor, Signer, Verifier, Hasher. Each wrapper is bound to a
// goland type representing either an option or a key.
type CSP struct {
	ks bccsp.KeyStore

	KeyGenerators map[reflect.Type]KeyGenerator
	KeyDerivers   map[reflect.Type]KeyDeriver
	KeyImporters  map[reflect.Type]KeyImporter
	Encryptors    map[reflect.Type]Encryptor
	Decryptors    map[reflect.Type]Decryptor
	Signers       map[reflect.Type]Signer
	Verifiers     map[reflect.Type]Verifier
	Hashers       map[reflect.Type]Hasher
}

func New(keyStore bccsp.KeyStore) (*CSP, error) {
	if keyStore == nil {
		return nil, errors.Errorf("Invalid bccsp.KeyStore instance. It must be different from nil.")
	}

	encryptors := make(map[reflect.Type]Encryptor)
	decryptors := make(map[reflect.Type]Decryptor)
	signers := make(map[reflect.Type]Signer)
	verifiers := make(map[reflect.Type]Verifier)
	hashers := make(map[reflect.Type]Hasher)
	keyGenerators := make(map[reflect.Type]KeyGenerator)
	keyDerivers := make(map[reflect.Type]KeyDeriver)
	keyImporters := make(map[reflect.Type]KeyImporter)

	csp := &CSP{keyStore,
		keyGenerators, keyDerivers, keyImporters, encryptors,
		decryptors, signers, verifiers, hashers}

	return csp, nil
}

//根据key生成选项opts生成一个key
func (csp *CSP) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil.")
	}

	keyGenerator, found := csp.KeyGenerators[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'KeyGenOpts' provided [%v]", opts)
	}

	k, err = keyGenerator.KeyGen(opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed generating key with opts [%v]", opts)
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing key [%s]", opts.Algorithm())
		}
	}

	return k, nil
}

//根据key获取选项opts从k中重新获取一个key
func (csp *CSP) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	keyDeriver, found := csp.KeyDerivers[reflect.TypeOf(k)]
	if !found {
		return nil, errors.Errorf("Unsupported 'Key' provided [%v]", k)
	}

	k, err = keyDeriver.KeyDeriv(k, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed deriving key with opts [%v]", opts)
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing key [%s]", opts.Algorithm())
		}
	}

	return k, nil
}

//根据key导入选项opts从一个key原始的数据中导入一个key
func (csp *CSP) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if raw == nil {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}
	fmt.Println("KeyImporter:", opts)
	keyImporter, found := csp.KeyImporters[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'KeyImportOpts' provided [%v]", opts)
	}

	k, err = keyImporter.KeyImport(raw, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed importing key with opts [%v]", opts)
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing imported key with opts [%v]", opts)
		}
	}

	return
}

//根据SKI返回与该接口实例有联系的key
func (csp *CSP) GetKey(ski []byte) (k bccsp.Key, err error) {
	k, err = csp.ks.GetKey(ski)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed getting key for SKI [%v]", ski)
	}

	return
}

//根据哈希选项opts哈希一个消息msg，如果opts为空，则使用默认选项
func (csp *CSP) Hash(msg []byte, opts bccsp.HashOpts) (digest []byte, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	hasher, found := csp.Hashers[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'HashOpt' provided [%v]", opts)
	}

	digest, err = hasher.Hash(msg, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed hashing with opts [%v]", opts)
	}

	return
}

//根据哈希选项opts获取hash.Hash实例，如果opts为空，则使用默认选项
func (csp *CSP) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	hasher, found := csp.Hashers[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'HashOpt' provided [%v]", opts)
	}

	h, err = hasher.GetHash(opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed getting hash function with opts [%v]", opts)
	}

	return
}

//根据签名者选项opts，使用k对digest进行签名，注意如果需要对一个特别大的消息的hash值
//进行签名，调用者则负责对该特别大的消息进行hash后将其作为digest传入
func (csp *CSP) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty.")
	}

	signer, found := csp.Signers[reflect.TypeOf(k)]
	if !found {
		return nil, errors.Errorf("Unsupported 'SignKey' provided [%s]", k)
	}

	signature, err = signer.Sign(k, digest, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed signing with opts [%v]", opts)
	}

	return
}

//根据鉴定者选项opts，通过对比k和digest，鉴定签名
func (csp *CSP) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// Validate arguments
	if k == nil {
		return false, errors.New("Invalid Key. It must not be nil.")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty.")
	}
	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty.")
	}

	verifier, found := csp.Verifiers[reflect.TypeOf(k)]
	if !found {
		return false, errors.Errorf("Unsupported 'VerifyKey' provided [%v]", k)
	}

	valid, err = verifier.Verify(k, signature, digest, opts)
	if err != nil {
		return false, errors.Wrapf(err, "Failed verifing with opts [%v]", opts)
	}

	return
}

//根据加密者选项opts，使用k加密plaintext
func (csp *CSP) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}

	encryptor, found := csp.Encryptors[reflect.TypeOf(k)]
	if !found {
		return nil, errors.Errorf("Unsupported 'EncryptKey' provided [%v]", k)
	}

	return encryptor.Encrypt(k, plaintext, opts)
}

//根据解密者选项opts，使用k对ciphertext进行解密
func (csp *CSP) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}

	decryptor, found := csp.Decryptors[reflect.TypeOf(k)]
	if !found {
		return nil, errors.Errorf("Unsupported 'DecryptKey' provided [%v]", k)
	}

	plaintext, err = decryptor.Decrypt(k, ciphertext, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed decrypting with opts [%v]", opts)
	}

	return
}

// AddWrapper binds the passed type to the passed wrapper.
// Notice that that wrapper must be an instance of one of the following interfaces:
// KeyGenerator, KeyDeriver, KeyImporter, Encryptor, Decryptor, Signer, Verifier, Hasher.
func (csp *CSP) AddWrapper(t reflect.Type, w interface{}) error {
	if t == nil {
		return errors.Errorf("type cannot be nil")
	}
	if w == nil {
		return errors.Errorf("wrapper cannot be nil")
	}
	switch dt := w.(type) {
	case KeyGenerator:
		csp.KeyGenerators[t] = dt
	case KeyImporter:
		csp.KeyImporters[t] = dt
	case KeyDeriver:
		csp.KeyDerivers[t] = dt
	case Encryptor:
		csp.Encryptors[t] = dt
	case Decryptor:
		csp.Decryptors[t] = dt
	case Signer:
		csp.Signers[t] = dt
	case Verifier:
		csp.Verifiers[t] = dt
	case Hasher:
		csp.Hashers[t] = dt
	default:
		return errors.Errorf("wrapper type not valid, must be on of: KeyGenerator, KeyDeriver, KeyImporter, Encryptor, Decryptor, Signer, Verifier, Hasher")
	}
	return nil
}
