package main

type Command uint8

var (
	PublishMixDescriptor Command = 1
	AddConsensusDocument Command = 2
	AddNewAuthority      Command = 3
	GetConsensus         Command = 4
	Vote                 Command = 5
	VoteStatus           Command = 6
	Reveal               Command = 7
	RevealStatus         Command = 8
)
