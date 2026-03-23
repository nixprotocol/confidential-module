package types

// Module is the config object for the confidential module.
// This replaces the protobuf-generated module config type.
type Module struct {
	// Authority defines the custom module authority.
	// If not set, defaults to the governance module.
	Authority string `json:"authority,omitempty"`
}

// ProtoMessage, Reset, String implement proto.Message interface for compatibility.
func (*Module) ProtoMessage()    {}
func (m *Module) Reset()         { *m = Module{} }
func (m *Module) String() string { return "confidential/Module" }

// GovModuleName is the module name of the governance module.
const GovModuleName = "gov"
