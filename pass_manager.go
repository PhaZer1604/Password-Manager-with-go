package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type PasswordManager struct {
	passwords map[string][]byte
}

func NewPasswordManager() *PasswordManager {
	return &PasswordManager{
		passwords: make(map[string][]byte),
	}
}

func (ps *PasswordManager) Load_file(path string) error {
	values, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	records := strings.Split(string(values), "\n")
	for _, record := range records {
		data := strings.Split(record, ":")
		if len(data) == 2 {
			email := data[0]
			encryptedPass := []byte(data[1])
			ps.passwords[email] = encryptedPass
		}
	}
	return nil
}

func (ps *PasswordManager) Add_Password(website, pass string) error {
	encryptedPass, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	ps.passwords[website] = encryptedPass
	return nil
}

func (ps *PasswordManager) Verify_Password(website, pass string) (string, bool) {
	encryptedPass := ps.passwords[website]

	err := bcrypt.CompareHashAndPassword(encryptedPass, []byte(pass))
	if err != nil {
		return "", false
	}

	return string(encryptedPass), true
}

func (ps *PasswordManager) Save_File(path string) error {
	var records []string
	for website, encryptedPass := range ps.passwords {
		record := fmt.Sprintf("%s:%s\n", website, string(encryptedPass))
		records = append(records, record)
	}

	data := []byte(strings.Join(records, ""))
	err := ioutil.WriteFile(path, data, 0644)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	manager := NewPasswordManager()

	path := "passwords.txt"

	if _, err := os.Stat(path); err == nil {
		err := manager.Load_file(path)
		if err != nil {
			fmt.Println("Error loading passwords:", err)
		}
	}

	for {
		fmt.Println("-----Password Manager-----")
		fmt.Println("1. Add Password")
		fmt.Println("2. Verify Password")
		fmt.Println("3. Save & Quit")

		var ch int
		fmt.Scan(&ch)
		switch ch {

		case 1:
			fmt.Print("Enter Website name: ")
			var website, pass string
			fmt.Scan(&website)
			fmt.Print("Enter password: ")
			fmt.Scan(&pass)

			err := manager.Add_Password(website, pass)
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Println("Password added successfully!!!")
			}

		case 2:
			fmt.Print("Enter Website name: ")
			var website, pass string
			fmt.Scan(&website)
			fmt.Print("Enter password: ")
			fmt.Scan(&pass)

			_, ok := manager.Verify_Password(website, pass)
			if ok {
				fmt.Println("Password correct.")
			} else {
				fmt.Println("Password incorrect or not found.")
			}

		case 3:
			err := manager.Save_File(path)
			if err != nil {
				fmt.Println("Error saving passwords: ", err)
			} else {
				fmt.Println("Passwords saved successfully. CLosing program....")
			}
			return

		default:
			fmt.Println("Invalid choice. Please try again.")
		}
		fmt.Println()
	}
}
