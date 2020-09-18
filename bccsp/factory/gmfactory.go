package factory

import (
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/gm"
)

const (
	// GuomiBasedFactoryName is the name of the factory of the software-based BCCSP implementation
	GuomiBasedFactoryName = "GM"
)

// GMFactory is the factory of the guomi-based BCCSP.
type GMFactory struct{}

// Name returns the name of this factory
func (f *GMFactory) Name() string {
	return GuomiBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *GMFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	fmt.Println("Get")
	if config == nil || config.SW == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	gmOpts := config.SW
	fmt.Println("gmOpts.FileKeystore:", gmOpts.FileKeystore)
	var ks bccsp.KeyStore
	switch {
	case gmOpts.FileKeystore != nil:
		fks, err := gm.NewFileBasedKeyStore(nil, gmOpts.FileKeystore.KeyStorePath, false)
		if err != nil {
			return nil, fmt.Errorf("Failed to initialize gm software key store: %s", err)
		}
		ks = fks
	default:
		// Default to ephemeral key store
		ks = gm.NewDummyKeyStore()
	}

	return gm.NewWithParams(gmOpts.Security, gmOpts.Hash, ks)
}

// 	var ks bccsp.KeyStore
// 	if gmOpts.Ephemeral == true {
// 		ks = gm.NewDummyKeyStore()
// 	} else if gmOpts.FileKeystore != nil {
// 		fks, err := gm.NewFileBasedKeyStore(nil, gmOpts.FileKeystore.KeyStorePath, false)
// 		if err != nil {
// 			return nil, fmt.Errorf("Failed to initialize gm software key store: %s", err)
// 		}
// 		ks = fks
// 	} else {
// 		// Default to DummyKeystore
// 		ks = gm.NewDummyKeyStore()
// 	}

// 	return gm.New(gmOpts.SecLevel, "GMSM3", ks)
// 	//return gm.New(gmOpts.SecLevel, gmOpts.HashFamily, ks)
// }
