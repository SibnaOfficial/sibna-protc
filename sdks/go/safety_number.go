package sibna

import (
	"fmt"
	"strconv"
	"strings"
)

// ── SafetyNumber ───────────────────────────────────────────────────────────

type SafetyNumber struct {
	Digits      string
	Fingerprint []byte
	Version     int
}

const SafetyNumberVersion = 1

func SafetyNumberCalculate(ourIdentity, theirIdentity []byte) *SafetyNumber {
	first, second := sortKeys(ourIdentity, theirIdentity)

	data := make([]byte, 0, 1+22+len(first)+len(second))
	data = append(data, SafetyNumberVersion)
	data = append(data, []byte("SIBNA_SAFETY_NUMBER_V1")...)
	data = append(data, first...)
	data = append(data, second...)

	hash := SHA512(data)
	fingerprint := hash[:32]
	digits := bytesToDigits(fingerprint)

	return &SafetyNumber{
		Digits:      digits,
		Fingerprint: fingerprint,
		Version:     SafetyNumberVersion,
	}
}

func SafetyNumberCalculateWithExtra(ourIdentity, theirIdentity, extraData []byte) *SafetyNumber {
	first, second := sortKeys(ourIdentity, theirIdentity)

	data := make([]byte, 0, 1+27+len(first)+len(second)+len(extraData))
	data = append(data, SafetyNumberVersion)
	data = append(data, []byte("SIBNA_SAFETY_NUMBER_V1_EXTRA")...)
	data = append(data, first...)
	data = append(data, second...)
	data = append(data, extraData...)

	hash := SHA512(data)
	fingerprint := hash[:32]
	digits := bytesToDigits(fingerprint)

	return &SafetyNumber{
		Digits:      digits,
		Fingerprint: fingerprint,
		Version:     SafetyNumberVersion,
	}
}

func SafetyNumberFromString(s string) (*SafetyNumber, error) {
	var digitBuilder strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digitBuilder.WriteRune(c)
		}
	}
	digits := digitBuilder.String()
	if len(digits) != 80 {
		return nil, fmt.Errorf("expected 80 digits, got %d", len(digits))
	}
	fingerprint := digitsToBytes(digits)
	return &SafetyNumber{
		Digits:      digits,
		Fingerprint: fingerprint,
		Version:     SafetyNumberVersion,
	}, nil
}

func (sn *SafetyNumber) AsString() string {
	return sn.Digits
}

func (sn *SafetyNumber) Formatted(groupSize, groupsPerLine int) string {
	if groupSize == 0 {
		groupSize = 5
	}
	if groupsPerLine == 0 {
		groupsPerLine = 8
	}
	var groups []string
	for i := 0; i < len(sn.Digits); i += groupSize {
		end := i + groupSize
		if end > len(sn.Digits) {
			end = len(sn.Digits)
		}
		groups = append(groups, sn.Digits[i:end])
	}
	var lines []string
	for i := 0; i < len(groups); i += groupsPerLine {
		end := i + groupsPerLine
		if end > len(groups) {
			end = len(groups)
		}
		lines = append(lines, strings.Join(groups[i:end], " "))
	}
	return strings.Join(lines, "\n")
}

func (sn *SafetyNumber) QRData() []byte {
	data := make([]byte, 0, 36)
	data = append(data, byte(sn.Version))
	data = append(data, []byte("SB1")...)
	data = append(data, sn.Fingerprint...)
	return data
}

func (sn *SafetyNumber) Verify(other *SafetyNumber) bool {
	k := make([]byte, 32)
	a := HMACSHA256(k, sn.Fingerprint)
	b := HMACSHA256(k, other.Fingerprint)
	return hmacEqual(a, b)
}

func (sn *SafetyNumber) String() string {
	return sn.Formatted(5, 8)
}

func (sn *SafetyNumber) Equal(other *SafetyNumber) bool {
	if len(sn.Fingerprint) != len(other.Fingerprint) {
		return false
	}
	for i := range sn.Fingerprint {
		if sn.Fingerprint[i] != other.Fingerprint[i] {
			return false
		}
	}
	return true
}

// ── Internal helpers ──────────────────────────────────────────────────────

func sortKeys(a, b []byte) ([]byte, []byte) {
	if less(a, b) {
		return a, b
	}
	return b, a
}

func less(a, b []byte) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return len(a) < len(b)
}

func bytesToDigits(data []byte) string {
	var parts []string
	for i := 0; i < len(data); i += 2 {
		value := int(data[i])<<8 | int(data[i+1])
		s := fmt.Sprintf("%05d", value%100000)
		parts = append(parts, s)
	}
	return strings.Join(parts, "")
}

func digitsToBytes(digits string) []byte {
	result := make([]byte, 0, 32)
	for i := 0; i < len(digits); i += 5 {
		chunk := digits[i : i+5]
		value, _ := strconv.Atoi(chunk)
		result = append(result, byte((value>>8)&0xFF))
		result = append(result, byte(value&0xFF))
	}
	return result
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
