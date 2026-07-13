package dsl

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"go.starlark.net/starlark"
)

type nodeRef struct {
	id        string
	operation string
}

func (reference nodeRef) String() string {
	return fmt.Sprintf("<lrail %s %s>", reference.operation, reference.id)
}

func (reference nodeRef) Type() string {
	return "lrail." + reference.operation
}

func (reference nodeRef) Freeze() {}

func (reference nodeRef) Truth() starlark.Bool {
	return starlark.True
}

func (reference nodeRef) Hash() (uint32, error) {
	return starlark.String(reference.operation + ":" + reference.id).Hash()
}

type shellCommand struct {
	arguments []string
}

func (command shellCommand) String() string {
	return "<lrail explicit shell command>"
}

func (command shellCommand) Type() string {
	return "lrail.shell_command"
}

func (command shellCommand) Freeze() {}

func (command shellCommand) Truth() starlark.Bool {
	return starlark.True
}

func (command shellCommand) Hash() (uint32, error) {
	digest := sha256.Sum256([]byte(command.arguments[2]))
	return binary.BigEndian.Uint32(digest[:4]), nil
}

type outputRef struct {
	name string
	kind string
}

func (reference outputRef) String() string {
	return fmt.Sprintf("<lrail %s output %s>", reference.kind, reference.name)
}

func (reference outputRef) Type() string {
	return "lrail.output"
}

func (reference outputRef) Freeze() {}

func (reference outputRef) Truth() starlark.Bool {
	return starlark.True
}

func (reference outputRef) Hash() (uint32, error) {
	return starlark.String(reference.kind + ":" + reference.name).Hash()
}
