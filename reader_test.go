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

type readerMockCall struct {
	ReqLen int
	ResLen int
	ResErr error
}

type readerStep struct {
	BufLen      int
	MockCall    *readerMockCall
	ExpectedLen int
	ExpectedErr error
}

type readerTest struct {
	Name    string
	Padding *paddingMock
	Steps   []readerStep
}

func TestReader(t *testing.T) {
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
	originalBytes := make([]byte, 32*aesCipher.BlockSize())
	_, err = rand.Read(originalBytes)
	if err != nil {
		t.Fatal(err)
	}

	expectedBytes := make([]byte, len(originalBytes))
	cipher.NewCBCEncrypter(aesCipher, iv).CryptBlocks(expectedBytes, originalBytes)

	// Prepare a custom error
	testErr := fmt.Errorf("test error")

	// Prepare test cases
	testCases := []readerTest{
		{
			Name: "VariousReadPatterns",
			Steps: []readerStep{
				// Read the first 3 bytes of the first block.
				// The reader should try to read the first block entirely but we only provide the first 5 bytes.
				// Nothing should be returned because the first block is incomplete.
				{
					BufLen: 3,
					MockCall: &readerMockCall{
						ReqLen: 16,
						ResLen: 5,
						ResErr: nil,
					},
					ExpectedLen: 0,
					ExpectedErr: nil,
				},
				// Try again.
				// The reader should try to read the rest of the first block but we only provide the next 5 bytes.
				// Nothing should be returned because the first block is still incomplete.
				{
					BufLen: 3,
					MockCall: &readerMockCall{
						ReqLen: 11,
						ResLen: 5,
						ResErr: nil,
					},
					ExpectedLen: 0,
					ExpectedErr: nil,
				},
				// Try again.
				// The reader should try to read the rest of the first block and we fullfil its request.
				// The first 3 bytes should be finally available since the first block is now complete.
				{
					BufLen: 3,
					MockCall: &readerMockCall{
						ReqLen: 6,
						ResLen: 6,
						ResErr: nil,
					},
					ExpectedLen: 3,
					ExpectedErr: nil,
				},
				// Read the next 5 bytes of the first block.
				// They should be available without calling the mock again.
				{
					BufLen:      5,
					MockCall:    nil,
					ExpectedLen: 5,
					ExpectedErr: nil,
				},
				// Read the last 8 bytes of the first block.
				// They should be available without calling the mock again.
				{
					BufLen:      8,
					MockCall:    nil,
					ExpectedLen: 8,
					ExpectedErr: nil,
				},
				// Read one block and a half.
				// The reader should to read all of them but only the first block should be returned.
				{
					BufLen: 24,
					MockCall: &readerMockCall{
						ReqLen: 24,
						ResLen: 24,
						ResErr: nil,
					},
					ExpectedLen: 16,
					ExpectedErr: nil,
				},
				// Read more than one block again (20 bytes).
				// The reader should reuse 8 bytes from the previous step and read the rest.
				// One block should be returned
				{
					BufLen: 20,
					MockCall: &readerMockCall{
						ReqLen: 12,
						ResLen: 12,
						ResErr: nil,
					},
					ExpectedLen: 16,
					ExpectedErr: nil,
				},
				// Read the rest of the last block.
				// The reader should reuse 4 bytes from the previous step and read the rest.
				// One block should be returned
				{
					BufLen: 16,
					MockCall: &readerMockCall{
						ReqLen: 12,
						ResLen: 12,
						ResErr: nil,
					},
					ExpectedLen: 16,
					ExpectedErr: nil,
				},
				// Read zero byte.
				// The reader should not try to read anything.
				{
					BufLen:      0,
					MockCall:    nil,
					ExpectedLen: 0,
					ExpectedErr: nil,
				},
				// Read exactly 3 blocks and reach EOF.
				{
					BufLen: 48,
					MockCall: &readerMockCall{
						ReqLen: 48,
						ResLen: 48,
						ResErr: io.EOF,
					},
					ExpectedLen: 48,
					ExpectedErr: io.EOF,
				},
				// Read after EOF.
				// The reader should not attempt to call the mock.
				{
					BufLen:      16,
					MockCall:    nil,
					ExpectedLen: 0,
					ExpectedErr: io.EOF,
				},
			},
		},
		{
			Name: "SmallBufEmptyReader",
			Steps: []readerStep{
				{
					BufLen: 12,
					MockCall: &readerMockCall{
						ReqLen: 16,
						ResLen: 0,
						ResErr: io.EOF,
					},
					ExpectedLen: 0,
					ExpectedErr: io.EOF,
				},
			},
		},
		{
			Name: "LargeBufEmptyReader",
			Steps: []readerStep{
				{
					BufLen: 24,
					MockCall: &readerMockCall{
						ReqLen: 24,
						ResLen: 0,
						ResErr: io.EOF,
					},
					ExpectedLen: 0,
					ExpectedErr: io.EOF,
				},
			},
		},
		{
			Name: "SmallBufEOFWithData",
			Steps: []readerStep{
				{
					BufLen: 12,
					MockCall: &readerMockCall{
						ReqLen: 16,
						ResLen: 16,
						ResErr: io.EOF,
					},
					ExpectedLen: 12,
					ExpectedErr: nil,
				},
				{
					BufLen:      12,
					MockCall:    nil,
					ExpectedLen: 4,
					ExpectedErr: io.EOF,
				},
			},
		},
		{
			Name: "LargeBufEOFWithData",
			Steps: []readerStep{
				{
					BufLen: 24,
					MockCall: &readerMockCall{
						ReqLen: 24,
						ResLen: 16,
						ResErr: io.EOF,
					},
					ExpectedLen: 16,
					ExpectedErr: io.EOF,
				},
			},
		},
		{
			Name: "SmallBufEOFAfterData",
			Steps: []readerStep{
				{
					BufLen: 12,
					MockCall: &readerMockCall{
						ReqLen: 16,
						ResLen: 16,
						ResErr: nil,
					},
					ExpectedLen: 12,
					ExpectedErr: nil,
				},
				{
					BufLen: 12,
					MockCall: &readerMockCall{
						ReqLen: 16,
						ResLen: 0,
						ResErr: io.EOF,
					},
					ExpectedLen: 4,
					ExpectedErr: io.EOF,
				},
			},
		},
		{
			Name: "LargeBufEOFAfterData",
			Steps: []readerStep{
				{
					BufLen: 24,
					MockCall: &readerMockCall{
						ReqLen: 24,
						ResLen: 16,
						ResErr: nil,
					},
					ExpectedLen: 16,
					ExpectedErr: nil,
				},
				{
					BufLen: 24,
					MockCall: &readerMockCall{
						ReqLen: 24,
						ResLen: 0,
						ResErr: io.EOF,
					},
					ExpectedLen: 0,
					ExpectedErr: io.EOF,
				},
			},
		},
		{
			Name: "SmallBufUnexpectedEOF",
			Steps: []readerStep{
				{
					BufLen: 3,
					MockCall: &readerMockCall{
						ReqLen: 16,
						ResLen: 5,
						ResErr: nil,
					},
					ExpectedLen: 0,
					ExpectedErr: nil,
				},
				{
					BufLen: 3,
					MockCall: &readerMockCall{
						ReqLen: 11,
						ResLen: 5,
						ResErr: io.EOF,
					},
					ExpectedLen: 0,
					ExpectedErr: io.ErrUnexpectedEOF,
				},
			},
		},
		{
			Name: "LargeBufUnexpectedEOF",
			Steps: []readerStep{
				{
					BufLen: 32,
					MockCall: &readerMockCall{
						ReqLen: 32,
						ResLen: 24,
						ResErr: io.EOF,
					},
					ExpectedLen: 16,
					ExpectedErr: io.ErrUnexpectedEOF,
				},
			},
		},
		{
			Name: "SmallBufErr",
			Steps: []readerStep{
				{
					BufLen: 3,
					MockCall: &readerMockCall{
						ReqLen: 16,
						ResLen: 5,
						ResErr: nil,
					},
					ExpectedLen: 0,
					ExpectedErr: nil,
				},
				{
					BufLen: 3,
					MockCall: &readerMockCall{
						ReqLen: 11,
						ResLen: 5,
						ResErr: testErr,
					},
					ExpectedLen: 0,
					ExpectedErr: testErr,
				},
			},
		},
		{
			Name: "SmallBufErrWithData",
			Steps: []readerStep{
				{
					BufLen: 3,
					MockCall: &readerMockCall{
						ReqLen: 16,
						ResLen: 5,
						ResErr: nil,
					},
					ExpectedLen: 0,
					ExpectedErr: nil,
				},
				{
					BufLen: 3,
					MockCall: &readerMockCall{
						ReqLen: 11,
						ResLen: 11,
						ResErr: testErr,
					},
					ExpectedLen: 3,
					ExpectedErr: nil,
				},
				{
					BufLen:      13,
					MockCall:    nil,
					ExpectedLen: 13,
					ExpectedErr: testErr,
				},
			},
		},
		{
			Name: "LargeBufErr",
			Steps: []readerStep{
				{
					BufLen: 32,
					MockCall: &readerMockCall{
						ReqLen: 32,
						ResLen: 24,
						ResErr: testErr,
					},
					ExpectedLen: 16,
					ExpectedErr: testErr,
				},
			},
		},
		{
			Name: "SmallBufPadding",
			Padding: &paddingMock{
				Len: 6,
			},
			Steps: []readerStep{
				{
					BufLen: 3,
					MockCall: &readerMockCall{
						ReqLen: 16,
						ResLen: 5,
						ResErr: nil,
					},
					ExpectedLen: 0,
					ExpectedErr: nil,
				},
				{
					BufLen: 3,
					MockCall: &readerMockCall{
						ReqLen: 11,
						ResLen: 5,
						ResErr: io.EOF,
					},
					ExpectedLen: 3,
					ExpectedErr: nil,
				},
				{
					BufLen:      16,
					MockCall:    nil,
					ExpectedLen: 13,
					ExpectedErr: io.EOF,
				},
			},
		},
		{
			Name: "LargeBufPadding",
			Padding: &paddingMock{
				Len: 8,
			},
			Steps: []readerStep{
				{
					BufLen: 32,
					MockCall: &readerMockCall{
						ReqLen: 32,
						ResLen: 24,
						ResErr: io.EOF,
					},
					ExpectedLen: 32,
					ExpectedErr: io.EOF,
				},
			},
		},
		{
			Name: "LargeBufExceedingPadding",
			Padding: &paddingMock{
				Len: 8,
			},
			Steps: []readerStep{
				{
					BufLen: 28,
					MockCall: &readerMockCall{
						ReqLen: 28,
						ResLen: 24,
						ResErr: io.EOF,
					},
					ExpectedLen: 28,
					ExpectedErr: nil,
				},
				{
					BufLen:      16,
					MockCall:    nil,
					ExpectedLen: 4,
					ExpectedErr: io.EOF,
				},
			},
		},
		{
			Name: "SmallBufErrNoPadding",
			Padding: &paddingMock{
				Len: -1,
			},
			Steps: []readerStep{
				{
					BufLen: 12,
					MockCall: &readerMockCall{
						ReqLen: 16,
						ResLen: 3,
						ResErr: testErr,
					},
					ExpectedLen: 0,
					ExpectedErr: testErr,
				},
			},
		},
		{
			Name: "LargeBufErrNoPadding",
			Padding: &paddingMock{
				Len: -1,
			},
			Steps: []readerStep{
				{
					BufLen: 32,
					MockCall: &readerMockCall{
						ReqLen: 32,
						ResLen: 24,
						ResErr: testErr,
					},
					ExpectedLen: 16,
					ExpectedErr: testErr,
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

			mock := mocks.NewMockReader(mockCtrl)
			blockMode := cipher.NewCBCEncrypter(aesCipher, iv)

			var lastMockCall *gomock.Call
			originalOffset := 0
			expectedOffset := 0

			var reader io.Reader
			if testCase.Padding != nil {
				padding := testCase.Padding.NewMock(mockCtrl, cipherio.PaddingFunc(func(dst []byte) {
					copy(dst, originalBytes[originalOffset:])
				}))
				reader = cipherio.NewBlockReaderWithPadding(mock, blockMode, padding)
			} else {
				reader = cipherio.NewBlockReader(mock, blockMode)
			}

			for _, step := range testCase.Steps {
				buf := make([]byte, step.BufLen)

				if step.MockCall != nil {
					mockCall := mock.EXPECT().Read(gomock.Len(step.MockCall.ReqLen)).DoAndReturn(func(p []byte) (int, error) {
						copy(p[:step.MockCall.ResLen], originalBytes[originalOffset:])
						originalOffset += step.MockCall.ResLen
						return step.MockCall.ResLen, step.MockCall.ResErr
					})
					if lastMockCall != nil {
						mockCall.After(lastMockCall)
					}
					lastMockCall = mockCall
				}

				n, err := reader.Read(buf)

				if n != step.ExpectedLen {
					t.Fatalf("unexpected read length: %d != %d", n, step.ExpectedLen)
				}
				if err != step.ExpectedErr {
					t.Fatalf("unexpected read err: %v != %v", err, step.ExpectedErr)
				}
				if !bytes.Equal(buf[:n], expectedBytes[expectedOffset:expectedOffset+n]) {
					t.Fatalf("unexpected read bytes")
				}
				expectedOffset += n
			}
		})
	}
}
