package cipherio_test

import (
	"bytes"
	"testing"

	"github.com/connesc/cipherio"
)

type paddingTest struct {
	Name     string
	Padding  cipherio.Padding
	Expected []byte
}

func TestPadding(t *testing.T) {
	testCases := []paddingTest{
		{
			Name:     "ZeroPadding",
			Padding:  cipherio.ZeroPadding,
			Expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			Name:     "BitPadding",
			Padding:  cipherio.BitPadding,
			Expected: []byte{0x80, 0x00, 0x00, 0x00, 0x00},
		},
		{
			Name:     "PKCS7Padding",
			Padding:  cipherio.PKCS7Padding,
			Expected: []byte{0x05, 0x05, 0x05, 0x05, 0x05},
		},
	}

	for index := range testCases {
		testCase := testCases[index]

		t.Run(testCase.Name, func(t *testing.T) {
			buf := make([]byte, len(testCase.Expected))
			testCase.Padding.Fill(buf)
			if !bytes.Equal(buf, testCase.Expected) {
				t.Fatalf("unexpected padding result")
			}
		})
	}

}
