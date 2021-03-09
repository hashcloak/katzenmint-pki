package main

type Command uint8

var (
	PublishMixDescriptor Command = 1
	AddConsensusDocument Command = 2
	AddNewAuthority      Command = 3
	GetConsensus         Command = 4
)
