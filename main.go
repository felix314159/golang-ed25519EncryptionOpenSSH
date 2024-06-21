package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	// libp2p
	libp2pCrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func main() {
	// get ed25519 keypair (currently libp2p crypto is not compatible with some crypto/ssh functions, so instead of libp2p use crypto/ed25519)
	/*
	privKey, pubKey, err := libp2pCrypto.GenerateKeyPair(
		libp2pCrypto.Ed25519,
		-1, // this value is only used for RSA keys (https://github.com/libp2p/go-libp2p/blob/v0.35.1/core/crypto/key.go#L108)
	)
	*/
	pubKey, privKey, err := ed25519.GenerateKey(nil) // nil will use crypto/rand.Reader
	if err != nil {
		panic(fmt.Sprintf("genkey - %v", err))
	}
	
	// even if you derive libp2p privkey from privkey, you will still get the same error 'unsupported key type *crypto.Ed25519PrivateKey' with MarshalPrivateKeyWithPassphrase()
	//libp2pPrivkey, err := libp2pCrypto.UnmarshalEd25519PrivateKey(privKey)
	//if err != nil {
	//	panic(err)
	//}

	myPassword := "badpassword"
	keyOutputPath := filepath.Join(".", "privkey.key")
	comment := "no comment" // purely cosmetic (but commands like 'ssh-keygen -y -f privkey.key' will display the comment)
	EncryptKeyAndWriteToFile(privKey, myPassword, keyOutputPath, comment)

	// now read this encrypted key again from filesystem
	retrievedKey := ReadKeyFromFileAndDecrypt(myPassword, keyOutputPath)

	// compare with original, should be true if everything went well
	if string(retrievedKey) != string(privKey) {
		panic("Original and retrieved keys are not identical, something went wrong!")
	}

	// derive ssh pubkey
	sshPubkey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		panic(fmt.Sprintf("NewSignerFromSigner - %v", err))
	}

	// derive libp2p pubkey from pubkey
	libp2pPubkey, err := libp2pCrypto.UnmarshalEd25519PublicKey(pubKey)
	if err != nil {
		panic(err)
	}
	// derive libp2p nodeid from libp2p pubkey
	peerID, err := peer.IDFromPublicKey(libp2pPubkey)
	if err != nil {
		panic(err)
	}

	pubKeyString := string(ssh.MarshalAuthorizedKey(sshPubkey))
	pubKeyStringWithComment := strings.TrimRight(pubKeyString, "\n\r") + " " + comment
	fmt.Printf("Public Key: %v\n", pubKeyStringWithComment)
	fmt.Printf("Libp2p Node ID: %v\n", peerID.String())

	// verify correctness with external tool (enter correct password)
	//	  ssh-keygen -y -f privkey.key
	// will print same pubkey
}

// EncryptKeyAndWriteToFile takes a private ed25519 key, a password and a filepath string and writes the encrypted key in OpenSSH format to that location.
func EncryptKeyAndWriteToFile(privkey ed25519.PrivateKey, password string, outputLocation string, comment string) {
	// encrypt private key into OpenSSH format
	pwBytes := []byte(password)
	encryptedPEM, err := ssh.MarshalPrivateKeyWithPassphrase(privkey, comment, pwBytes)
	if err != nil {
		panic(fmt.Sprintf("encrypt - %v", err))
	}

	// encode PEM to bytes
	//encryptedPEMBytes := pem.EncodeToMemory(encryptedPEM)

	// check if file exists already, warn user that it will be deleted (technically truncated). in production maybe require explicit confirmation before doing this
	_, err = os.Stat(outputLocation)
	if err == nil { // this is useful for automated testing, change in production
		fmt.Printf("Warning: There already exists a keyfile at %v. It will be overwritten!\n", outputLocation)
	}

	// write pem to file
	//		open file
	file, err := os.Create(outputLocation)
    if err != nil {
        panic(fmt.Sprintf("Failed to create key file: %v\n", err))
    }
    defer file.Close()

    //		write to file
	err = pem.Encode(file, encryptedPEM)
	if err != nil {
		panic(fmt.Sprintf("Failed to write PEM key to file: %v\n", err))
	}

	// set file permission to 600 (otherwise tools like ssh-keygen will complain that permissions are too open and refuse to do anything)
	err = os.Chmod(outputLocation, 0600)
	if err != nil {
		panic(fmt.Sprintf("Failed to set private key file permission: %v", err))
	}

}

// ReadKeyFromFileAndDecrypt takes the password that the key was encrypted with and the location of the key and returns the decrypted ed25519.PrivateKey)
func ReadKeyFromFileAndDecrypt(password string, keyLocation string) ed25519.PrivateKey {
	// try to read encrypted key from file if it exists
	encryptedPEMBytes, err := os.ReadFile(keyLocation)
	if err != nil {
		panic(fmt.Sprintf("Failed to read the keyfile %v: %v", keyLocation, err))
	}

	// decrypt encrypted private key
	decryptedPrivInterface, err := ssh.ParseRawPrivateKeyWithPassphrase(encryptedPEMBytes, []byte(password))
	if err != nil {
		panic(err) // false password triggers: 'x509: decryption password incorrect'
	}

	// cast from interface to ed25519 key
	decryptedPrivPtr, ok := decryptedPrivInterface.(*ed25519.PrivateKey)
	if !ok {
		panic(fmt.Sprintf("Key is not of type ed25519.PrivateKey, instead it is of type: %T\n", decryptedPrivInterface))
	}

	return *decryptedPrivPtr
}