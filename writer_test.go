package cipherio_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/connesc/cipherio"
	"github.com/connesc/cipherio/internal/mocks"
)

type writerMockCall struct {
	ReqLen int
	ResLen int
	ResErr error
}

type writeAction struct {
	BufLen      int
	ExpectedLen int
	ExpectedErr error
}

type closeAction struct {
	ExpectedErr error
}

type writerStep struct {
	Action    interface{}
	MockCalls []writerMockCall
}

type writerTest struct {
	Name    string
	Padding *paddingMock
	Steps   []writerStep
}

func TestWriter(t *testing.T) {
	// Generate a random AES key
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	// Initialize the AES-CBC encrypter
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	iv := make([]byte, aesCipher.BlockSize())
	_, err = rand.Read(iv)
	if err != nil {
		t.Fatal(err)
	}

	// Generate random test data
	originalBytes := make([]byte, 1056*aesCipher.BlockSize())
	_, err = rand.Read(originalBytes)
	if err != nil {
		t.Fatal(err)
	}

	expectedBytes := make([]byte, len(originalBytes))
	cipher.NewCBCEncrypter(aesCipher, iv).CryptBlocks(expectedBytes, originalBytes)

	// Prepare a custom error
	testErr := fmt.Errorf("test error")
	_ = testErr // TODO

	// Prepare test cases
	testCases := []writerTest{
		{
			Name: "VariousWritePatterns",
			Steps: []writerStep{
				// Write the first 3 bytes of the first block.
				// The writer should not call the mock because the block is incomplete.
				{
					Action: writeAction{
						BufLen:      3,
						ExpectedLen: 3,
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{},
				},
				// Write the 6 next bytes of the first block.
				// The writer should now have 9 bytes in its internal buffer.
				{
					Action: writeAction{
						BufLen:      6,
						ExpectedLen: 6,
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{},
				},
				// Write 20 additional bytes.
				// This should complete the first block and leave 13 bytes in the internal buffer.
				// The mock should be called with the first encrypted block.
				{
					Action: writeAction{
						BufLen:      20,
						ExpectedLen: 20,
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{
						{
							ReqLen: 16,
							ResLen: 16,
							ResErr: nil,
						},
					},
				},
				// Write 1025 complete blocks plus 9 bytes.
				// This should complete the last block, then fill 1025 blocks and then leave 6
				// bytes in the internal buffer.
				// Since there are 1026 encrypted blocks to write, the mock should be called twice.
				{
					Action: writeAction{
						BufLen:      1025*16 + 9,
						ExpectedLen: 1025*16 + 9,
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{
						{
							ReqLen: 1024 * 16,
							ResLen: 1024 * 16,
							ResErr: nil,
						},
						{
							ReqLen: 32,
							ResLen: 32,
							ResErr: nil,
						},
					},
				},
				// Write 42 additional bytes.
				// This should complete the last block, then fill 2 blocks and then leave the
				// internal buffer empty.
				// The mock should be called with the 3 encrypted blocks.
				{
					Action: writeAction{
						BufLen:      42,
						ExpectedLen: 42,
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{
						{
							ReqLen: 48,
							ResLen: 48,
							ResErr: nil,
						},
					},
				},
				// Write exactly 3 blocks.
				// The internal buffer should remain empty.
				// The mock should be called with the 3 encrypted blocks.
				{
					Action: writeAction{
						BufLen:      48,
						ExpectedLen: 48,
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{
						{
							ReqLen: 48,
							ResLen: 48,
							ResErr: nil,
						},
					},
				},
				// Close the writer.
				// This should succeed since the internal buffer is supposed to be empty.
				{
					Action: closeAction{
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{},
				},
				// Close the writer again.
				// This should be a no-op.
				{
					Action: closeAction{
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{},
				},
			},
		},
		{
			Name: "UnexpectedEOF",
			Steps: []writerStep{
				{
					Action: writeAction{
						BufLen:      3,
						ExpectedLen: 3,
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{},
				},
				{
					Action: closeAction{
						ExpectedErr: io.ErrUnexpectedEOF,
					},
					MockCalls: []writerMockCall{},
				},
				{
					Action: closeAction{
						ExpectedErr: io.ErrUnexpectedEOF,
					},
					MockCalls: []writerMockCall{},
				},
			},
		},
		{
			Name: "WriteErr",
			Steps: []writerStep{
				{
					Action: writeAction{
						BufLen:      20,
						ExpectedLen: 12,
						ExpectedErr: testErr,
					},
					MockCalls: []writerMockCall{
						{
							ReqLen: 16,
							ResLen: 12,
							ResErr: testErr,
						},
					},
				},
				{
					Action: writeAction{
						BufLen:      3,
						ExpectedLen: 0,
						ExpectedErr: testErr,
					},
					MockCalls: []writerMockCall{},
				},
				{
					Action: closeAction{
						ExpectedErr: testErr,
					},
					MockCalls: []writerMockCall{},
				},
				{
					Action: closeAction{
						ExpectedErr: testErr,
					},
					MockCalls: []writerMockCall{},
				},
			},
		},
		{
			Name: "WriteErrWithBuffer",
			Steps: []writerStep{
				{
					Action: writeAction{
						BufLen:      3,
						ExpectedLen: 3,
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{},
				},
				{
					Action: writeAction{
						BufLen:      20,
						ExpectedLen: 9,
						ExpectedErr: testErr,
					},
					MockCalls: []writerMockCall{
						{
							ReqLen: 16,
							ResLen: 12,
							ResErr: testErr,
						},
					},
				},
				{
					Action: writeAction{
						BufLen:      3,
						ExpectedLen: 0,
						ExpectedErr: testErr,
					},
					MockCalls: []writerMockCall{},
				},
				{
					Action: closeAction{
						ExpectedErr: testErr,
					},
					MockCalls: []writerMockCall{},
				},
				{
					Action: closeAction{
						ExpectedErr: testErr,
					},
					MockCalls: []writerMockCall{},
				},
			},
		},
		{
			Name: "WriteErrWithBufferOnly",
			Steps: []writerStep{
				{
					Action: writeAction{
						BufLen:      3,
						ExpectedLen: 3,
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{},
				},
				{
					Action: writeAction{
						BufLen:      20,
						ExpectedLen: 0,
						ExpectedErr: testErr,
					},
					MockCalls: []writerMockCall{
						{
							ReqLen: 16,
							ResLen: 2,
							ResErr: testErr,
						},
					},
				},
				{
					Action: writeAction{
						BufLen:      3,
						ExpectedLen: 0,
						ExpectedErr: testErr,
					},
					MockCalls: []writerMockCall{},
				},
				{
					Action: closeAction{
						ExpectedErr: testErr,
					},
					MockCalls: []writerMockCall{},
				},
				{
					Action: closeAction{
						ExpectedErr: testErr,
					},
					MockCalls: []writerMockCall{},
				},
			},
		},
		{
			Name: "Padding",
			Padding: &paddingMock{
				Len: 13,
			},
			Steps: []writerStep{
				{
					Action: writeAction{
						BufLen:      3,
						ExpectedLen: 3,
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{},
				},
				{
					Action: closeAction{
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{
						{
							ReqLen: 16,
							ResLen: 16,
							ResErr: nil,
						},
					},
				},
				{
					Action: closeAction{
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{},
				},
			},
		},
		{
			Name: "PaddingErr",
			Padding: &paddingMock{
				Len: 13,
			},
			Steps: []writerStep{
				{
					Action: writeAction{
						BufLen:      3,
						ExpectedLen: 3,
						ExpectedErr: nil,
					},
					MockCalls: []writerMockCall{},
				},
				{
					Action: closeAction{
						ExpectedErr: testErr,
					},
					MockCalls: []writerMockCall{
						{
							ReqLen: 16,
							ResLen: 12,
							ResErr: testErr,
						},
					},
				},
				{
					Action: closeAction{
						ExpectedErr: testErr,
					},
					MockCalls: []writerMockCall{},
				},
			},
		},
	}

	// Run test cases
	for index := range testCases {
		testCase := testCases[index]

		t.Run(testCase.Name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mock := mocks.NewMockWriter(mockCtrl)
			blockMode := cipher.NewCBCEncrypter(aesCipher, iv)

			var lastMockCall *gomock.Call
			originalOffset := 0
			expectedOffset := 0

			var writer io.WriteCloser
			if testCase.Padding != nil {
				padding := testCase.Padding.NewMock(mockCtrl, cipherio.PaddingFunc(func(dst []byte) {
					copy(dst, originalBytes[originalOffset:])
				}))
				writer = cipherio.NewBlockWriterWithPadding(mock, blockMode, padding)
			} else {
				writer = cipherio.NewBlockWriter(mock, blockMode)
			}

			for _, step := range testCase.Steps {
				for index := range step.MockCalls {
					mockCallSpec := step.MockCalls[index]

					mockCall := mock.EXPECT().Write(gomock.Len(mockCallSpec.ReqLen)).DoAndReturn(func(p []byte) (int, error) {
						if !bytes.Equal(p, expectedBytes[expectedOffset:expectedOffset+len(p)]) {
							t.Fatalf("unexpected write bytes")
						}
						expectedOffset += len(p)
						return mockCallSpec.ResLen, mockCallSpec.ResErr
					})

					if lastMockCall != nil {
						mockCall.After(lastMockCall)
					}
					lastMockCall = mockCall
				}

				switch action := step.Action.(type) {
				case writeAction:
					src := originalBytes[originalOffset : originalOffset+action.BufLen]
					buf := append([]byte(nil), src...)

					n, err := writer.Write(buf)

					if n != action.ExpectedLen {
						t.Fatalf("unexpected write length: %d != %d", n, action.ExpectedLen)
					}
					if err != action.ExpectedErr {
						t.Fatalf("unexpected write err: %v != %v", err, action.ExpectedErr)
					}
					if !bytes.Equal(buf, src) {
						t.Fatalf("unexpected modification in write buffer")
					}
					originalOffset += n

				case closeAction:
					err := writer.Close()

					if err != action.ExpectedErr {
						t.Fatalf("unexpected close err: %v != %v", err, action.ExpectedErr)
					}
				}
			}
		})
	}
}
