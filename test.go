package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func main() {
	key := []byte("example key 1234")

	result, err := AesEncrypt([]byte("Hello World!"), key)
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(result)) //VRMzYJwT5xx0bvqud3Np+g==

	r, _ := base64.StdEncoding.DecodeString("dpepq82KQTeL+9qqcNJ5DMCFXlQH3Zc2Kh49+Ro1gHY=") // use CryptoJs encrypted
	//r := result  // decrypt go encrypted
	origData, err := AesDecrypt(r, key)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(origData)) // exampleplaintext
}

func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	iv := []byte("1234567812345678")
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := []byte("1234567812345678")
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// package main
// import (
//     "crypto/aes"
//     "crypto/cipher"
//     "crypto/rand"
//     "encoding/base64"
//     "fmt"
// 	"log"
// )





// func encrypt(secretKey []byte, plaintext string)string{
// 	 // Create the AES cipher block
// 	 block, err := aes.NewCipher(secretKey)
// 	 if err != nil {
// 		 fmt.Println("Error creating cipher block:", err)
// 		 return ""
// 	 }
 
// 	 // Create a GCM encrypter
// 	 gcm, err := cipher.NewGCM(block)
// 	 if err != nil {
// 		 fmt.Println("Error creating GCM encrypter:", err)
// 		 return ""
// 	 }
 
// 	 // Generate a random nonce
// 	 nonce := make([]byte, gcm.NonceSize())
// 	 if _, err := rand.Read(nonce); err != nil {
// 		 fmt.Println("Error generating nonce:", err)
// 		 return ""
// 	 }
 
// 	 // Encrypt the data
// 	 ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
 
// 	 // Encode the encrypted data to base64
// 	 encryptedData := base64.StdEncoding.EncodeToString(append(nonce, ciphertext...))
 
// 	 fmt.Println("Encrypted data:", encryptedData)
// 	 return string(encryptedData)
// }

// func decrypt(secretKey []byte, encryptedData string)string {
//     // Decode the base64-encoded encrypted data
//     encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedData)
//     if err != nil {
//         fmt.Println("Error decoding base64:", err)
//         return ""
//     }

//     // Create the AES cipher block
//     block, err := aes.NewCipher(secretKey)
//     if err != nil {
//         fmt.Println("Error creating cipher block:", err)
//         return ""
//     }

//     // Create a GCM decrypter
//     gcm, err := cipher.NewGCM(block)
//     if err != nil {
//         fmt.Println("Error creating GCM decrypter:", err)
//         return ""
//     }

//     // Get the nonce from the encrypted data
//     nonceSize := gcm.NonceSize()
//     nonce, ciphertext := encryptedBytes[:nonceSize], encryptedBytes[nonceSize:]

//     // Decrypt the data
//     decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
//     if err != nil {
//         fmt.Println("Error decrypting data:", err)
//         return ""
//     }

//     fmt.Println("Decrypted data:", string(decryptedData))
// 	return string(decryptedData)
// }

// func DecryptAES(encryptedData, key []byte) ([]byte, error) {
//     block, err := aes.NewCipher(key)
//     if err != nil {
//         return nil, err
//     }
    
//     gcm, err := cipher.NewGCM(block)
//     if err != nil {
//         return nil, err
//     }
    
//     nonceSize := gcm.NonceSize()
//     nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
    
//     decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
//     if err != nil {
//         return nil, err
//     }
    
//     return decryptedData, nil
// }




// func main(){
// 	secretKey := []byte("idvvfRl09DpqmmOLvi4x9zR06c1z31LS")
// 	encryptedPassword := "U2FsdGVkX1+t+OV/OVN3tIozKeeKh8hCf5w94HiiXQs="
// 	// encpt := encrypt(secretKey, plaintext)
// 	// log.Println(decrypt(secretKey, encpt))
// 	//log.Println(DecryptAES(plaintext, secretKey))
// 	// Handle the request and get the encrypted password


// 	// Decrypt the password
// 	decryptedBytes, err := DecryptAES([]byte(encryptedPassword), secretKey)
// 	if err != nil {
// 		// Handle decryption error
// 		log.Println(err)
// 	}

// 	// Convert decrypted bytes to string
// 	decryptedPassword := string(decryptedBytes)
// 	log.Println(decryptedPassword)

// }
