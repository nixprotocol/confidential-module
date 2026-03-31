package types

import (
	"testing"
)

func validParams() Params {
	return Params{
		AuditorPubKey:   nil,
		MaxTransferBits: 64,
	}
}

func TestValidate_DefaultParams(t *testing.T) {
	if err := DefaultParams().Validate(); err != nil {
		t.Fatalf("default params should be valid: %v", err)
	}
}

func TestValidate_MaxTransferBits(t *testing.T) {
	tests := []struct {
		name    string
		value   int32
		wantErr bool
	}{
		{"zero", 0, true},
		{"negative", -1, true},
		{"min valid", 1, false},
		{"max valid", 64, false},
		{"above max", 65, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validParams()
			p.MaxTransferBits = tc.value
			err := p.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("MaxTransferBits=%d: got err=%v, wantErr=%v", tc.value, err, tc.wantErr)
			}
		})
	}
}

func TestValidate_AuditorPubKey(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr bool
	}{
		{"nil", nil, false},
		{"empty", []byte{}, false},
		{"valid length", make([]byte, 64), false},
		{"too short", make([]byte, 32), true},
		{"too long", make([]byte, 128), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validParams()
			p.AuditorPubKey = tc.key
			err := p.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("AuditorPubKey len=%d: got err=%v, wantErr=%v", len(tc.key), err, tc.wantErr)
			}
		})
	}
}
