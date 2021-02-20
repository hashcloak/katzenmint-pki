package main

type Command int

var (
	PublishMixDescriptor Command = 1
	AddConsensusDocument Command = 2
	AddNewAuthority      Command = 3
)
