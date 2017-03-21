//author :Ally Dale(vipally@gmail.com)
//date: 2017-03-21

//tool encode is a tool to make a github repository privately.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/vipally/cmdline"
)

var (
	path                  = "."
	keyfile               = "c:/encode/rsa"
	decode                = false //解密
	genkey                = false
	privateKey, publicKey []byte
	encodehead            = []byte("|#e!n#c%o^d&e*h(e)a-d+|")
)

func main() {
	cmdline.Summary("tool encode is a tool to make a github repository privately.")
	cmdline.Details("")
	cmdline.StringVar(&keyfile, "k", "keyfile", keyfile, false, "keyfile")
	cmdline.StringVar(&path, "p", "path", path, false, "path")
	cmdline.BoolVar(&decode, "d", "decode", decode, false, "decode flag")
	cmdline.BoolVar(&genkey, "g", "genkey", genkey, false, "genkey")
	cmdline.Parse()
	if genkey {
		genRsaKey(keyfile, 4096)
	} else {
		initKeys()
		s := "E:\\dev\\gocode\\trunk\\src\\github.com\\vipally\\encode\\test.gox"
		if decode {
			RsaDecryptFile(s)
		} else {
			RsaEncryptFile(s)
		}
	}
	//wd, _ := os.Getwd()
	//fmt.Println(wd)
}

func keyFile(public bool) (file string) {
	if public {
		file = keyfile + "_public.pem"
	} else {
		file = keyfile + "_private.pem"
	}
	return
}

func genRsaKey(keyfile string, bits int) error {
	// 生成私钥文件
	prifile, err := os.OpenFile(keyFile(false), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer prifile.Close()

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "private key",
		Bytes: derStream,
	}

	err = pem.Encode(prifile, block)
	if err != nil {
		return err
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "public key",
		Bytes: derPkix,
	}
	pubfile, err := os.OpenFile(keyFile(true), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return err
	}
	defer pubfile.Close()
	err = pem.Encode(pubfile, block)
	if err != nil {
		return err
	}
	return nil
}

func initKeys() {
	var err error
	publicKey, err = ioutil.ReadFile(keyFile(true))
	if err != nil {
		panic(err)
	}
	privateKey, err = ioutil.ReadFile(keyFile(false))
	if err != nil {
		panic(err)
	}
}

func checkFileHead(b []byte) bool {
	if len(b) < len(encodehead) {
		return false
	}
	for i := 0; i < len(encodehead); i++ {
		if b[i] != encodehead[i] {
			return false
		}
	}
	return true
}

func RsaEncryptFile(file string) (err error) {
	var src, dst []byte
	if src, err = ioutil.ReadFile(file); err == nil {
		if !checkFileHead(src) { //没加密过的
			if dst, err = RsaEncrypt(src); err == nil {
				if file, err2 := os.Create(file); err2 == nil {
					defer file.Close()
					file.Write(encodehead) //先写head
					if _, err3 := file.Write(dst); err3 != nil {
						err = err3
					}
				} else {
					err = err2
				}
			}
		}
	}
	if err != nil {
		panic(err)
	}
	return
}
func RsaDecryptFile(file string) (err error) {
	var src, dst []byte
	if src, err = ioutil.ReadFile(file); err == nil {
		if checkFileHead(src) { //加密过的
			if dst, err = RsaEncrypt(src[:len(encodehead)]); err == nil {
				if file, err2 := os.Create(file); err2 == nil {
					defer file.Close()
					if _, err3 := file.Write(dst); err3 != nil {
						err = err3
					}
				} else {
					err = err2
				}
			}
		}
	}
	if err != nil {
		panic(err)
	}
	return
}

// 加密
func RsaEncrypt(origData []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

// 解密
func RsaDecrypt(ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}
