package incident

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// signatureContext separates approval signatures from any other use of an operator's key.
const signatureContext = "cad-approval-v1\n"

// Operators maps trusted operator names to their Ed25519 public keys.
type Operators map[string]ed25519.PublicKey

// OperatorEntry is one line of an operators file.
type OperatorEntry struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

type operatorsFile struct {
	Operators []OperatorEntry `json:"operators"`
}

// LoadOperators reads a trusted operators file. Names and keys must each be
// unique, so one person cannot count twice under two names.
func LoadOperators(r io.Reader) (Operators, error) {
	var f operatorsFile
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: operators file: %v", ErrRefused, err)
	}
	if len(f.Operators) == 0 {
		return nil, fmt.Errorf("%w: operators file lists no operators", ErrRefused)
	}
	ops := Operators{}
	seenKey := map[string]string{}
	for _, e := range f.Operators {
		if err := validText("operator name", e.Name, maxOperatorLen); err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.DecodeString(e.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: operator %q has an invalid public key", ErrRefused, e.Name)
		}
		if _, dup := ops[e.Name]; dup {
			return nil, fmt.Errorf("%w: operator %q is listed twice", ErrRefused, e.Name)
		}
		if other, dup := seenKey[e.PublicKey]; dup {
			return nil, fmt.Errorf("%w: operators %q and %q share a key", ErrRefused, other, e.Name)
		}
		seenKey[e.PublicKey] = e.Name
		ops[e.Name] = ed25519.PublicKey(raw)
	}
	return ops, nil
}

// KeyFile is an operator's private key as stored on disk.
type KeyFile struct {
	Operator   string `json:"operator"`
	PrivateKey string `json:"private_key"`
}

// GenerateKey creates a key pair for an operator and returns the private key
// file contents and the entry to add to the operators file.
func GenerateKey(operator string) (KeyFile, OperatorEntry, error) {
	if err := validText("operator", operator, maxOperatorLen); err != nil {
		return KeyFile{}, OperatorEntry{}, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyFile{}, OperatorEntry{}, err
	}
	return KeyFile{Operator: operator, PrivateKey: base64.StdEncoding.EncodeToString(priv)},
		OperatorEntry{Name: operator, PublicKey: base64.StdEncoding.EncodeToString(pub)}, nil
}

// LoadKey reads a private key file and returns the operator it belongs to.
func LoadKey(r io.Reader) (string, ed25519.PrivateKey, error) {
	var k KeyFile
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&k); err != nil {
		// Never include file contents in the error: it is a private key.
		return "", nil, fmt.Errorf("%w: key file is not valid", ErrRefused)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k.PrivateKey))
	if err != nil || len(raw) != ed25519.PrivateKeySize || k.Operator == "" {
		return "", nil, fmt.Errorf("%w: key file is not valid", ErrRefused)
	}
	return k.Operator, ed25519.PrivateKey(raw), nil
}

// approvalMessage is what gets signed: every field of the approval except
// the signature itself. The finding record hash ties it to one finding.
func approvalMessage(a ApprovalData) ([]byte, error) {
	a.Signature = ""
	body, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return append([]byte(signatureContext), body...), nil
}

// SignApproval returns the base64 signature of an approval.
func SignApproval(a ApprovalData, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("%w: signing key is not valid", ErrRefused)
	}
	msg, err := approvalMessage(a)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, msg)), nil
}

// verify reports whether the approval is signed by its operator's trusted key.
func (o Operators) verify(a ApprovalData) bool {
	pub, ok := o[a.Operator]
	if !ok || a.Signature == "" {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return false
	}
	msg, err := approvalMessage(a)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}
