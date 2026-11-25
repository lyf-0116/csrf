package csrf

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestIssuedMaskedTokenLayoutIsOTPThenMasked(t *testing.T) {
	realToken := bytes.Repeat([]byte{0x11}, tokenLength)
	otp := bytes.Repeat([]byte{0xaa}, tokenLength)

	originalReader := rand.Reader
	rand.Reader = bytes.NewReader(otp)
	t.Cleanup(func() {
		rand.Reader = originalReader
	})

	encoded := mask(realToken, nil)
	issued, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode masked token: %v", err)
	}

	if len(issued) != maskedTokenLength {
		t.Fatalf("issued token length = %d, want %d", len(issued), maskedTokenLength)
	}

	maskedToken := xorToken(otp, realToken)
	if got := issued[:tokenLength]; !bytes.Equal(got, otp) {
		t.Fatalf("first half = %x, want OTP %x", got, otp)
	}
	if got := issued[tokenLength:]; !bytes.Equal(got, maskedToken) {
		t.Fatalf("second half = %x, want masked token %x", got, maskedToken)
	}
	if got := unmask(issued); !bytes.Equal(got, realToken) {
		t.Fatalf("unmasked token = %x, want %x", got, realToken)
	}
}

func TestPackUnpackMaskedTokenRoundTrip(t *testing.T) {
	otp := bytes.Repeat([]byte{0x22}, tokenLength)
	maskedToken := bytes.Repeat([]byte{0x33}, tokenLength)

	issued := packMaskedToken(otp, maskedToken)
	if !bytes.Equal(issued[:tokenLength], otp) {
		t.Fatal("packed token does not start with the OTP")
	}
	if !bytes.Equal(issued[tokenLength:], maskedToken) {
		t.Fatal("packed token does not end with the masked token")
	}

	gotOTP, gotMaskedToken := unpackMaskedToken(issued)
	if !bytes.Equal(gotOTP, otp) {
		t.Fatalf("unpacked OTP = %x, want %x", gotOTP, otp)
	}
	if !bytes.Equal(gotMaskedToken, maskedToken) {
		t.Fatalf("unpacked masked token = %x, want %x", gotMaskedToken, maskedToken)
	}

	for _, length := range []int{0, tokenLength - 1, tokenLength, maskedTokenLength - 1, maskedTokenLength + 1} {
		gotOTP, gotMaskedToken := unpackMaskedToken(make([]byte, length))
		if gotOTP != nil || gotMaskedToken != nil {
			t.Fatalf("unpack for length %d returned non-nil halves", length)
		}
	}
}

func TestUnmaskAcceptsHistoricallyIssuedLayout(t *testing.T) {
	realToken := bytes.Repeat([]byte{0x44}, tokenLength)
	otp := bytes.Repeat([]byte{0x55}, tokenLength)

	// Tokens issued by the old generator were already serialized as
	// OTP || (OTP XOR real token), even though unmask assigned those halves
	// to its local variables in the opposite order.
	historical := append(append([]byte{}, otp...), xorToken(otp, realToken)...)

	if got := unmask(historical); !bytes.Equal(got, realToken) {
		t.Fatalf("historical token unmasked to %x, want %x", got, realToken)
	}
}
