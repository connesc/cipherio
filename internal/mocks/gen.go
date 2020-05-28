//go:generate go run github.com/golang/mock/mockgen -destination io.go -package mocks io Reader,Writer
//go:generate go run github.com/golang/mock/mockgen -destination cipherio.go -package mocks github.com/connesc/cipherio Padding

package mocks
