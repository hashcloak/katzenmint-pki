## Overview

We propose a mixnet PKI system using Tendermint as its consensus engine. Tendermint is a general purpose, state machine replication system. Validators in the Tendermint system vote on blocks of transactions and upon receiving enough votes, the block gets commits to a hash chain of blocks, known as a blockchain.

In this system, authorities act as Tendermint validators and handle the chain's consensus. In addition to their responsibilities as validators, they still carry out their responsibilities as outlined in (insert link to katzenpost pki spec).

Valid consensus documents, mix descriptors and authority set changes are different transactions types that are batched into blocks and voted upon by authorities. 

Mix nodes and clients use the Tendermint light client system to retrieve information from the blockchain without having the responsilities of a full, Tendermint node. This reduces the communication mix nodes and clients need to do with validators. Mix nodes and clients' responsibilities remain the same as outlined in the katzenpost PKI spec.

Providers responsibilities' are reduced in this PKI system. They no longer need to cache consensus documents for clients to fetch. Instead, they can (perhaps MAY is a better term here) serve as full nodes for the overall availability of the Tendermint blockchain.

## Description

### Security Goals
The security goals of this Directory Authority system remain the same with the addition of the following goals and features:

- Byzantine-Fault tolerance: It allows for consensus faults between the directory authorities. Further, it is possible to find badly behaving operators in the system.
- The Directory Authority servers form a peer to peer gossip amongst themselves.

### Transaction Format
Currently, consensus documents are formatted as 
```
type Document struct {
	// Epoch is the epoch for which this Document instance is valid for.
	Epoch uint64

	// GenesisEpoch is the epoch on which authorities started consensus
	GenesisEpoch uint64

	// SendRatePerMinute is the number of packets per minute a client can send.
	SendRatePerMinute uint64

	// Mu is the inverse of the mean of the exponential distribution
	// that the Sphinx packet per-hop mixing delay will be sampled from.
	Mu float64

	// MuMaxDelay is the maximum Sphinx packet per-hop mixing delay in
	// milliseconds.
	MuMaxDelay uint64

	// LambdaP is the inverse of the mean of the exponential distribution
	// that clients will sample to determine the time interval between sending
	// messages from it's FIFO egress queue or drop decoy messages if the queue
	// is empty.
	LambdaP float64

	// LambdaPMaxDelay is the maximum time interval in milliseconds.
	LambdaPMaxDelay uint64

	// LambdaL is the inverse of the mean of the exponential distribution
	// that clients will sample to determine the time interval between sending
	// decoy loop messages.
	LambdaL float64

	// LambdaLMaxDelay is the maximum time interval in milliseconds.
	LambdaLMaxDelay uint64

	// LambdaD is the inverse of the mean of the exponential distribution
	// that clients will sample to determine the time interval between sending
	// decoy drop messages.
	LambdaD float64

	// LambdaDMaxDelay is the maximum time interval in milliseconds.
	LambdaDMaxDelay uint64

	// LambdaM is the inverse of the mean of the exponential distribution
	// that mixes will sample to determine send timing of mix loop decoy traffic.
	LambdaM float64

	// LambdaMMaxDelay is the maximum send interval in milliseconds.
	LambdaMMaxDelay uint64

	// Topology is the mix network topology, excluding providers.
	Topology [][]*MixDescriptor

	// Providers is the list of providers that can interact with the mix
	// network.
	Providers []*MixDescriptor

	// SharedRandomCommit used by the voting process.
	SharedRandomCommit []byte

	// SharedRandomValue produced by voting process.
	SharedRandomValue []byte

	// PriorSharedRandom used by applications that need a longer lived SRV.
	PriorSharedRandom [][]byte
}
```
where `MixDescriptor` is defined as 
```
type MixDescriptor struct {
	// Name is the human readable (descriptive) node identifier.
	Name string

	// IdentityKey is the node's identity (signing) key.
	IdentityKey *eddsa.PublicKey

	// LinkKey is the node's wire protocol public key.
	LinkKey *ecdh.PublicKey

	// MixKeys is a map of epochs to Sphinx keys.
	MixKeys map[uint64]*ecdh.PublicKey

	// Addresses is the map of transport to address combinations that can
	// be used to reach the node.
	Addresses map[Transport][]string

	// Kaetzchen is the map of provider autoresponder agents by capability
	// to parameters.
	Kaetzchen map[string]map[string]interface{} `json:",omitempty"`

	// RegistrationHTTPAddresses is a slice of HTTP URLs used for Provider
	// user registration. Providers of course may choose to set this to nil.
	RegistrationHTTPAddresses []string

	// Layer is the topology layer.
	Layer uint8

	// LoadWeight is the node's load balancing weight (unused).
	LoadWeight uint8
}
```

We make the following changes to the consensus document struct:
```
type Document struct {
	// Epoch is the epoch for which this Document instance is valid for.
	Epoch uint64

	// GenesisEpoch is the epoch on which authorities started consensus
	GenesisEpoch uint64

	// SendRatePerMinute is the number of packets per minute a client can send.
	SendRatePerMinute uint64

	// Mu is the inverse of the mean of the exponential distribution
	// that the Sphinx packet per-hop mixing delay will be sampled from.
	Mu float64

	// MuMaxDelay is the maximum Sphinx packet per-hop mixing delay in
	// milliseconds.
	MuMaxDelay uint64

	// LambdaP is the inverse of the mean of the exponential distribution
	// that clients will sample to determine the time interval between sending
	// messages from it's FIFO egress queue or drop decoy messages if the queue
	// is empty.
	LambdaP float64

	// LambdaPMaxDelay is the maximum time interval in milliseconds.
	LambdaPMaxDelay uint64

	// LambdaL is the inverse of the mean of the exponential distribution
	// that clients will sample to determine the time interval between sending
	// decoy loop messages.
	LambdaL float64

	// LambdaLMaxDelay is the maximum time interval in milliseconds.
	LambdaLMaxDelay uint64

	// LambdaD is the inverse of the mean of the exponential distribution
	// that clients will sample to determine the time interval between sending
	// decoy drop messages.
	LambdaD float64

	// LambdaDMaxDelay is the maximum time interval in milliseconds.
	LambdaDMaxDelay uint64

	// LambdaM is the inverse of the mean of the exponential distribution
	// that mixes will sample to determine send timing of mix loop decoy traffic.
	LambdaM float64

	// LambdaMMaxDelay is the maximum send interval in milliseconds.
	LambdaMMaxDelay uint64

	// Topology is the mix network topology, excluding providers.
	Topology [][]*MixDescriptor

	// Providers is the list of providers that can interact with the mix
	// network.
	Providers []*MixDescriptor
}
```

Now that we are using Tendermint, we will be considering the following transactions:
- `PublishMixDescriptor`: A transaction for posting mix descriptors by mix nodes. 
    - Transactions are of the form `serialized_mix_descriptor` 
        - where
            - `serialized_mix_descriptor` is a serialized form of the `MixDescriptor` Go struct. TODO: Explicitly write down how to serialize 
- `AddConsensusDoc`: A transaction for adding a new consensus document. 
    - Transactions are of the form `serialized_pki_doc` 
    - where 
        - `serialized_pki_doc` is the serialized form of a PKI consensus document as returned by `Get(Context, epoch)`. TODO: Explicitly write down the serialization procedure 
- `AddNewAuthority`: A transaction for adding a new authority node to the PKI System.
    - Transactions are of the form `auth:identity_pubkey;link_pubkey;power` 
        - where 
            - `auth` is known as the authority set change prefix
            - `identity_pubkey` is the authority's identity public key
            - `link_pubkey` is the authority's link public key
            - `power` is the authority's voting power. 
                - To remove an authority, set its voting power to 0.

### Configuration

#### Initialization
In order to define the behavior of this chain at startup, one needs to define the parameters in the `genesis.json` file. 

##### Parameters to set
- `genesis_time`: Time the blockchain starts. For our pursposes, this can be the time the mixnet starts.
- `chain_id`: ID of the blockchain. Effectively, this can change for major changes made to the blockchain. Can be used to delineate different versions of the chain.
- `consensus_params`:
    - `block`:
        - `time_iota_ms`: Minimum time increments between consecutive blocks. For our purposes, this will be time between epoch. The current katzenpost spec has this set to 3 hrs. However, the current implementation is set to 30 mins. TODO: Finalize epoch duration length
- `validators`: List of initial validators (authorities). We can set this at genesis or initialize it when we deploy the Tendermint-based PKI Authority.
    - `pub_key`: Ed25519 public keys where the first byte specifies the kind of key and the rest of the bytes specify the public key. TODO: Ensure that these keys can be converted to a more katzenpost friendly format.
    - `power`: validator's voting power. Initially, we can set this to 1. To remove an authority, set the voting power to 0. TODO: Determine ways to leverage this in the Katzenpost PKI authority.
- `app_hash`: expected application hash. Meant as a way to authenticate the application
- `app_state`: Application state. May not be directly relevant for our purposes as we don't have a token.

For more information about `genesis.json`, see https://github.com/tendermint/tendermint/blob/master/types/genesis.go

### Differences from current Katzenpost PKI system

The main differences between the current PKI system and this proposed system are:
- Authorities are selected in a round robin fashion to propose blocks as part of the tendermint consensus protocol.
- There is no randomness generation (NOTE: This can be added either through using Core Star's Tendermint fork or having a transaction that outputs the result of the regular shared randomness beacon)
- This tendermint-based authority system favors consistency over availability in a distributed systems sense.
- This protocol tolerates up to a 1/3 of authorities being byzantine.

## Privacy Considerations

- The list of authorities, mix descriptors and consensus documents are publicly posted on a public blockchain. Anyone can look at these transactions.
- Information retrieval using the light client system and transaction broadcasting are not privacy-preserving, by default, in Tendermint.


## Implementation Considerations
- Due to the blockchain structure, we might need to replace BoltDB, that is currently used in the voting PKI, with another DB that is optimized for both reads and writes (RocksDB and BadgerDB are good contenders for this). 
- Mix nodes and clients now need a tendermint light client in order to retrieve the latest view of the chain. 

## Future Considerations
- Incentivization via an external cryptocurrency (e.g. Zcash)
- Slashing penalties for misbehavior
- More permissionless enrollment of authorities
    - A Sybil-resistance mechanism for enrolling authorities
- PIR-like techniques for light clients
- Using [Core Star's Tendermint fork with an embedded BLS random beacon](https://github.com/corestario/tendermint)

## References
TODO: Add references
