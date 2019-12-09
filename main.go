package main

import (
	"flag"
	"fmt"
	mc "github.com/authapon/mcryptzero"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
)

var (
	en bool
	de bool
)

func init() {
	flag.BoolVar(&en, "encrypt", false, "Encryption Process")
	flag.BoolVar(&de, "decrypt", false, "Decryption Process")
}

func main() {
	flag.Parse()
	if en == de {
		flag.PrintDefaults()
		return
	}
	fmt.Printf("Password : ")
	pass1, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return
	}
	fmt.Printf("\nRe-type Password : ")
	pass2, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return
	}
	if string(pass1) != string(pass2) {
		fmt.Printf("\nPassword are not match!!!\n")
		return
	}

	fmt.Printf("\n\n")

	files, err := ioutil.ReadDir(".")
	if err != nil {
		fmt.Printf("Error!!! to read file in directory\n\n")
		return
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		switch en {
		case true:
			fmt.Printf("Encrypt : %s : ", file.Name())
			encrypt(file.Name(), pass1)
			fmt.Printf(" -- Finnished\n")
		default:
			fmt.Printf("Decrypt : %s : ", file.Name())
			decrypt(file.Name(), pass1)
			fmt.Printf(" -- Finnished\n")
		}
	}
}

func isFileNameMoocrypt(fname string) bool {
	f := strings.Split(fname, ".moocrypt")
	if len(f) > 1 {
		if f[len(f)-1] == "" {
			return true
		}
	}
	return false
}

func encrypt(fname string, pass []byte) {
	if isFileNameMoocrypt(fname) {
		fmt.Printf("Skip!!!")
		return
	}

	if _, err := os.Stat(fname + ".moocrypt"); !os.IsNotExist(err) {
		fmt.Printf("Skip!!!")
		return
	}

	file, err := os.Open(fname)
	if err != nil {
		fmt.Printf("Error to open file!!!")
		return
	}
	defer file.Close()

	filex, err := os.Create(fname + ".moocrypt")
	if err != nil {
		fmt.Printf("Error to create file encryption!!!")
		return
	}
	defer filex.Close()
	salt := []byte{0, 0, 0, 0}
	bufRead := make([]byte, 102400)

	for {
		key := append(salt, pass...)
		key = append(key, salt...)

		n, err := file.Read(bufRead)
		if err != nil {
			fmt.Printf("Error to read file!!!")
			return
		}

		if n == 0 {
			break
		}

		bufEncrypt := mc.Encrypt(bufRead[:n], key)
		salt[0] = bufEncrypt[0]
		salt[1] = bufEncrypt[1]
		salt[2] = bufEncrypt[2]
		salt[3] = bufEncrypt[3]

		n2, err := filex.Write(bufEncrypt)
		if err != nil {
			fmt.Printf("Error to write file!!!")
			return
		}

		if n != n2 {
			fmt.Printf("Error between read and write file!!!")
			return
		}

		fmt.Printf("@")

		if n != 102400 {
			break
		}
	}
	os.Remove(fname)
}

func getFileNameNoMooCrypt(fname string) string {
	f := strings.Split(fname, ".")
	if len(f) > 1 {
		if f[len(f)-1] == "moocrypt" {
			f = f[:len(f)-1]
		}
		fn := ""
		for _, v := range f {
			fn = fn + "." + v
		}
		fn = fn[1:len(fn)]
		return fn
	}
	return f[0]
}

func decrypt(fname string, pass []byte) {
	if !isFileNameMoocrypt(fname) {
		fmt.Printf("Skip!!!")
		return
	}

	fnamex := getFileNameNoMooCrypt(fname)

	if _, err := os.Stat(fnamex); !os.IsNotExist(err) {
		fmt.Printf("Skip!!!")
		return
	}

	file, err := os.Open(fname)
	if err != nil {
		fmt.Printf("Error to open file!!!")
		return
	}
	defer file.Close()

	filex, err := os.Create(fnamex)
	if err != nil {
		fmt.Printf("Error to create file decryption!!!")
		return
	}
	defer filex.Close()
	salt := []byte{0, 0, 0, 0}
	bufRead := make([]byte, 102400)

	for {
		key := append(salt, pass...)
		key = append(key, salt...)

		n, err := file.Read(bufRead)
		if err != nil {
			fmt.Printf("Error to read file!!!")
			return
		}

		if n == 0 {
			break
		}

		bufDecrypt := mc.Decrypt(bufRead[:n], key)
		salt[0] = bufRead[0]
		salt[1] = bufRead[1]
		salt[2] = bufRead[2]
		salt[3] = bufRead[3]

		n2, err := filex.Write(bufDecrypt)
		if err != nil {
			fmt.Printf("Error to write file!!!")
			return
		}

		if n != n2 {
			fmt.Printf("Error between read and write file!!!")
			return
		}

		fmt.Printf("@")

		if n != 102400 {
			break
		}
	}
	os.Remove(fname)
}
