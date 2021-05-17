package config

import (
	"math"

	katconfig "github.com/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/core/crypto/rand"
)

const (
	DefaultLayers           = 3
	DefaultMinNodesPerLayer = 2
	// Note: These values are picked primarily for debugging and need to be changed to something more suitable for a production deployment at some point.
	defaultSendRatePerMinute    = 100
	defaultMu                   = 0.00025
	defaultMuMaxPercentile      = 0.99999
	defaultLambdaP              = 0.00025
	defaultLambdaPMaxPercentile = 0.99999
	defaultLambdaL              = 0.00025
	defaultLambdaLMaxPercentile = 0.99999
	defaultLambdaD              = 0.00025
	defaultLambdaDMaxPercentile = 0.99999
	defaultLambdaM              = 0.00025
	defaultLambdaMMaxPercentile = 0.99999
	absoluteMaxDelay            = 6 * 60 * 60 * 1000 // 6 hours.
)

var DefaultParameters = katconfig.Parameters{
	SendRatePerMinute: defaultSendRatePerMinute,
	Mu:                defaultMu,
	MuMaxDelay:        uint64(math.Min(rand.ExpQuantile(defaultMu, defaultMuMaxPercentile), absoluteMaxDelay)),
	LambdaP:           defaultLambdaP,
	LambdaPMaxDelay:   uint64(rand.ExpQuantile(defaultLambdaP, defaultLambdaPMaxPercentile)),
	LambdaL:           defaultLambdaL,
	LambdaLMaxDelay:   uint64(rand.ExpQuantile(defaultLambdaL, defaultLambdaLMaxPercentile)),
	LambdaD:           defaultLambdaD,
	LambdaDMaxDelay:   uint64(rand.ExpQuantile(defaultLambdaD, defaultLambdaDMaxPercentile)),
	LambdaM:           defaultLambdaM,
	LambdaMMaxDelay:   uint64(rand.ExpQuantile(defaultLambdaM, defaultLambdaMMaxPercentile)),
}
