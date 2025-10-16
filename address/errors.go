package address

import "errors"

var ErrFailedToGenerateOffCurvePublicKey = errors.New("failed to generate off curve public key")

var ErrAddressIdentifierNotHandled = errors.New("address identifier not handled")

var ErrSourceAddressIsGenerated = errors.New("source address is generated")

var ErrSourceIdentifierMatchesTargetIdentifier = errors.New("source identifier matches target identifier")

var ErrInvalidAddressSizeForPseudoConversion = errors.New("invalid address size for pseudo conversion")

var ErrGeneratedAddressIsSmartContractAddress = errors.New("generated address is smart contract address")
