// state.go - Katzenpost non-voting authority server state.
// Copyright (C) 2017  Yawning Angel.

package katzenmint

import (
	"fmt"

	"github.com/hashcloak/katzenmint-pki/s11n"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx/constants"
)

func (s *KatzenmintState) generateDocument() (*document, error) {
	s.Lock()
	defer s.Unlock()

	// Carve out the descriptors between providers and nodes.
	var providers [][]byte
	var nodes []*descriptor
	for _, v := range s.descriptors[s.currentEpoch] {
		if v.desc.Layer == pki.LayerProvider {
			providers = append(providers, v.raw)
		} else {
			nodes = append(nodes, v)
		}
	}

	// Assign nodes to layers.
	var topology [][][]byte
	if len(nodes) < s.layers*s.minNodesPerLayer {
		return nil, fmt.Errorf("insufficient descriptors uploaded")
	}
	if d, ok := s.documents[s.currentEpoch-1]; ok {
		topology = generateTopology(nodes, d.doc, s.layers)
	} else {
		topology = generateRandomTopology(nodes, s.layers)
	}

	// Build the Document.
	doc := &s11n.Document{
		Epoch:             s.currentEpoch,
		GenesisEpoch:      s.genesisEpoch,
		SendRatePerMinute: s.parameters.SendRatePerMinute,
		Mu:                s.parameters.Mu,
		MuMaxDelay:        s.parameters.MuMaxDelay,
		LambdaP:           s.parameters.LambdaP,
		LambdaPMaxDelay:   s.parameters.LambdaPMaxDelay,
		LambdaL:           s.parameters.LambdaL,
		LambdaLMaxDelay:   s.parameters.LambdaLMaxDelay,
		LambdaD:           s.parameters.LambdaD,
		LambdaDMaxDelay:   s.parameters.LambdaDMaxDelay,
		LambdaM:           s.parameters.LambdaM,
		LambdaMMaxDelay:   s.parameters.LambdaMMaxDelay,
		Topology:          topology,
		Providers:         providers,
	}

	// TODO: what to do with shared random value?

	// Serialize the Document.
	serialized, err := s11n.SerializeDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize document: %v", err)
	}

	// Ensure the document is sane.
	pDoc, err := s11n.VerifyAndParseDocument(serialized)
	if err != nil {
		return nil, fmt.Errorf("signed document failed validation: %v", err)
	}
	if pDoc.Epoch != s.currentEpoch {
		return nil, fmt.Errorf("signed document has invalid epoch: %v", pDoc.Epoch)
	}
	ret := &document{
		doc: pDoc,
		raw: serialized,
	}
	return ret, nil
}

func generateTopology(nodeList []*descriptor, doc *pki.Document, layers int) [][][]byte {
	nodeMap := make(map[[constants.NodeIDLength]byte]*descriptor)
	for _, v := range nodeList {
		id := v.desc.IdentityKey.ByteArray()
		nodeMap[id] = v
	}

	// Since there is an existing network topology, use that as the basis for
	// generating the mix topology such that the number of nodes per layer is
	// approximately equal, and as many nodes as possible retain their existing
	// layer assignment to minimise network churn.

	rng := rand.NewMath()
	targetNodesPerLayer := len(nodeList) / layers
	topology := make([][][]byte, layers)

	// Assign nodes that still exist up to the target size.
	for layer, nodes := range doc.Topology {
		// The existing nodes are examined in random order to make it hard
		// to predict which nodes will be shifted around.
		nodeIndexes := rng.Perm(len(nodes))
		for _, idx := range nodeIndexes {
			if len(topology[layer]) >= targetNodesPerLayer {
				break
			}

			id := nodes[idx].IdentityKey.ByteArray()
			if n, ok := nodeMap[id]; ok {
				// There is a new descriptor with the same identity key,
				// as an existing descriptor in the previous document,
				// so preserve the layering.
				topology[layer] = append(topology[layer], n.raw)
				delete(nodeMap, id)
			}
		}
	}

	// Flatten the map containing the nodes pending assignment.
	toAssign := make([]*descriptor, 0, len(nodeMap))
	for _, n := range nodeMap {
		toAssign = append(toAssign, n)
	}
	assignIndexes := rng.Perm(len(toAssign))

	// Fill out any layers that are under the target size, by
	// randomly assigning from the pending list.
	idx := 0
	for layer := range doc.Topology {
		for len(topology[layer]) < targetNodesPerLayer {
			n := toAssign[assignIndexes[idx]]
			topology[layer] = append(topology[layer], n.raw)
			idx++
		}
	}

	// Assign the remaining nodes.
	for layer := 0; idx < len(assignIndexes); idx++ {
		n := toAssign[assignIndexes[idx]]
		topology[layer] = append(topology[layer], n.raw)
		layer++
		layer = layer % len(topology)
	}

	return topology
}

func generateRandomTopology(nodes []*descriptor, layers int) [][][]byte {
	// If there is no node history in the form of a previous consensus,
	// then the simplest thing to do is to randomly assign nodes to the
	// various layers.

	rng := rand.NewMath()
	nodeIndexes := rng.Perm(len(nodes))
	topology := make([][][]byte, layers)
	for idx, layer := 0, 0; idx < len(nodes); idx++ {
		n := nodes[nodeIndexes[idx]]
		topology[layer] = append(topology[layer], n.raw)
		layer++
		layer = layer % len(topology)
	}

	return topology
}
