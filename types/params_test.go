package types

import (
	"testing"
)

func validParams() Params {
	return Params{
		AuditorPubKey:         nil,
		AuditorKeyGracePeriod: 100,
		EnabledDenoms:         []string{},
		MaxTransferBits:       64,
		RotationCooldown:      100,
		MaxMemoSize:           1024,
	}
}

func TestValidate_DefaultParams(t *testing.T) {
	if err := DefaultParams().Validate(); err != nil {
		t.Fatalf("default params should be valid: %v", err)
	}
}

func TestValidate_RotationCooldown(t *testing.T) {
	tests := []struct {
		name    string
		value   uint64
		wantErr bool
	}{
		{"zero", 0, true},
		{"min valid", 1, false},
		{"typical", 100, false},
		{"max valid", 1_000_000, false},
		{"above max", 1_000_001, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validParams()
			p.RotationCooldown = tc.value
			err := p.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("RotationCooldown=%d: got err=%v, wantErr=%v", tc.value, err, tc.wantErr)
			}
		})
	}
}

func TestValidate_AuditorKeyGracePeriod(t *testing.T) {
	tests := []struct {
		name    string
		value   uint64
		wantErr bool
	}{
		{"zero", 0, true},
		{"min valid", 1, false},
		{"typical", 100, false},
		{"max valid", 1_000_000, false},
		{"above max", 1_000_001, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validParams()
			p.AuditorKeyGracePeriod = tc.value
			err := p.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("AuditorKeyGracePeriod=%d: got err=%v, wantErr=%v", tc.value, err, tc.wantErr)
			}
		})
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

func TestValidate_MaxMemoSize(t *testing.T) {
	tests := []struct {
		name    string
		value   int32
		wantErr bool
	}{
		{"negative", -1, true},
		{"zero", 0, false},
		{"typical", 1024, false},
		{"max valid", 4096, false},
		{"above max", 4097, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validParams()
			p.MaxMemoSize = tc.value
			err := p.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("MaxMemoSize=%d: got err=%v, wantErr=%v", tc.value, err, tc.wantErr)
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

func TestValidate_EnabledDenoms(t *testing.T) {
	p := validParams()
	p.EnabledDenoms = []string{"uatom", ""}
	if err := p.Validate(); err == nil {
		t.Error("expected error for empty denom in list")
	}

	p.EnabledDenoms = []string{"uatom", "ibc/ABC"}
	if err := p.Validate(); err != nil {
		t.Errorf("valid denoms should pass: %v", err)
	}

	p.EnabledDenoms = []string{"uatom", "ibc/ABC", "uatom"}
	if err := p.Validate(); err == nil {
		t.Error("expected error for duplicate denom in list")
	}
}
