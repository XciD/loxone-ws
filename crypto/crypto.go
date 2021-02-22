package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"

	log "github.com/sirupsen/logrus"
)

// bytesToPublicKey bytes to public key
func BytesToPublicKey(pub string) (*rsa.PublicKey, error) {
	pub = strings.Replace(pub, "-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n", 1)
	pub = strings.Replace(pub, "-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----", 1)

	block, _ := pem.Decode([]byte(pub))

	if block == nil {
		return nil, errors.New("block is nil")
	}

	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		log.Debug("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("error during public key deserialization")
	}
	return key, nil
}

func ComputeHmac256(message string, secret string) string {
	key, _ := hex.DecodeString(secret)
	h := hmac.New(sha1.New, key)
	_, err := h.Write([]byte(message))
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func CreateEncryptKey(size int32) string {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(key)
}

func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) (string, error) {
	cipher, err := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipher), nil
}

func DecryptAES(cypherEncoded string, uniqueKey string, ivKey string) ([]byte, error) {
	key, _ := hex.DecodeString(uniqueKey)
	cypher, _ := base64.StdEncoding.DecodeString(cypherEncoded)

	ivDecoded, _ := hex.DecodeString(ivKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(cypher)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, ivDecoded)

	mode.CryptBlocks(cypher, cypher)

	return unpad(cypher, aes.BlockSize)
}

func unpad(data []byte, blockSize int) (output []byte, err error) {
	var dataLen = len(data)
	if dataLen == 0 {
		return output, errors.New("data is empty")
	}
	if dataLen%blockSize != 0 {
		return output, errors.New("data's length isn't a multiple of blockSize")
	}
	var paddingBytes = 0
	for data[dataLen-1-paddingBytes] == 0 {
		paddingBytes++
	}
	if paddingBytes > blockSize || paddingBytes <= 0 {
		return output, nil
	}
	output = data[0 : dataLen-paddingBytes]
	return output, nil
}

func pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(0)}, padding)
	return append(src, padtext...)
}

func EncryptAES(plainText string, uniqueKey string, ivKey string) (string, error) {
	key, _ := hex.DecodeString(uniqueKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil
	}

	ciphertext := pad([]byte(plainText))
	ivDecoded, _ := hex.DecodeString(ivKey)

	mode := cipher.NewCBCEncrypter(block, ivDecoded)
	mode.CryptBlocks(ciphertext, ciphertext)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Sha1Hash(data string) string {
	h := sha1.New() // #nosec
	_, err := h.Write([]byte(data))
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func Sha256Hash(data string) string {
	h := sha256.New()
	_, err := h.Write([]byte(data))
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(h.Sum(nil))
}
