package katzenmint

// query represents the query request
type query struct {
	// version
	Version string

	// Epoch
	Epoch uint64

	// command
	Command Command

	// payload
	Payload string
}
