package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func toBytes(value int64) []byte {
	var result []byte
	mask := int64(0xFF)
	shifts := [8]uint16{56, 48, 40, 32, 24, 16, 8, 0}
	for _, shift := range shifts {
		result = append(result, byte((value>>shift)&mask))
	}
	return result
}

func toUint32(bytes []byte) uint32 {
	return (uint32(bytes[0]) << 24) + (uint32(bytes[1]) << 16) +
		(uint32(bytes[2]) << 8) + uint32(bytes[3])
}

func oneTimePassword(key []byte, value []byte) uint32 {
	// sign the value using HMAC-SHA1
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(value)
	hash := hmacSha1.Sum(nil)

	// We're going to use a subset of the generated hash.
	// Using the last nibble (half-byte) to choose the index to start from.
	// This number is always appropriate as it's maximum decimal 15, the hash will
	// have the maximum index 19 (20 bytes of SHA1) and we need 4 bytes.
	offset := hash[len(hash)-1] & 0x0F

	// get a 32-bit (4-byte) chunk from the hash starting at offset
	hashParts := hash[offset : offset+4]

	// ignore the most significant bit as per RFC 4226
	hashParts[0] = hashParts[0] & 0x7F

	number := toUint32(hashParts)

	// size to 6 digits
	// one million is the first number with 7 digits so the remainder
	// of the division will always return < 7 digits
	pwd := number % 1000000

	return pwd
}

func getTOTP(secret string) {
	// Get hex from secret
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// generate a one-time password using the time at 30-second intervals
	epochSeconds := time.Now().Unix()
	pwd := oneTimePassword(key, toBytes(epochSeconds/30))

	secondsRemaining := 30 - (epochSeconds % 30)
	fmt.Printf("%06d (%d second(s) remaining)\n", pwd, secondsRemaining)
}

func updateConfig(file string, conf map[string]string) {
	jsondat, _ := json.Marshal(conf)
	ioutil.WriteFile(file, jsondat, 0777)
}

func main() {
	curUser, _ := user.Current()
	// create a config file if it doesnt exist yet
	filename := curUser.HomeDir + "/.2fauth"
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		f, err := os.Create(filename)
		if err != nil {
			panic(err)
		}
		f.Close()
	}

	// Read the config file
	file, e := ioutil.ReadFile(curUser.HomeDir + "/.2fauth")
	if e != nil {
		log.Fatal(e)
	}

	// Load the config
	configDat := make(map[string]string)
	json.Unmarshal(file, &configDat)

	var cmdList = &cobra.Command{
		Use:   "list [string to print]",
		Short: "list all accounts",
		Long:  `lists all accounts which have been registered with lets-auth`,
		Run: func(cmd *cobra.Command, args []string) {
			// Iterates through the map and prints the keys
			if len(configDat) > 0 {
				fmt.Println("Get the codes for an account by typing: 2fauth get [accountname]")
				for key := range configDat {
					fmt.Println(key)
				}
				return
			}
			fmt.Println("There are no accounts registered yet! please do so by typing: 2fauth set -h")
		},
	}

	var cmdGet = &cobra.Command{
		Use:   "get [accountname]",
		Short: "get account code",
		Long:  `prints the account auth code with time remaining`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				fmt.Println("Wrong arguments! Please check usage with: 2fauth get -h")
				return
			}
			if configDat[args[0]] != "" {
				// Gets the oneTimePassword with the time remaining
				getTOTP(configDat[args[0]])
				return
			}
			fmt.Println("Looks like " + args[0] + " is not in the list. For the list of accounts, please type: 2fauth list")
		},
	}

	var cmdSet = &cobra.Command{
		Use:   "set [accountname] [key]",
		Short: "set account key",
		Long:  "set the accounts 2FA key. Create an account if it doesnt exist and updates if it does",
		Run: func(cmd *cobra.Command, args []string) {
			// Update the config file just before exiting
			defer updateConfig(curUser.HomeDir+"/.2fauth", configDat)

			if len(args) < 2 {
				fmt.Println("Wrong arguments! Please check usage with: 2fauth set -h")
				return
			}

			// Get the secret and remove all the spaces
			secret := strings.Join(args[1:], "")
			secret = strings.Replace(secret, " ", "", -1)

			// Base32 strings need to multiple of 8, so padding is added if length is not multiple of 8
			if len(secret)%8 != 0 {
				lenPad := 8 - len(secret)%8
				secret = secret + strings.Repeat("=", lenPad)
			}

			// Finally string is uppercased
			secret = strings.ToUpper(secret)
			configDat[args[0]] = secret
		},
	}

	var cmdDelete = &cobra.Command{
		Use:   "delete [accountname]",
		Short: "delete account key",
		Long:  "deletes an account. Does nothing if account doesnt exist",
		Run: func(cmd *cobra.Command, args []string) {
			// Update the config file just before exiting
			defer updateConfig(curUser.HomeDir+"/.2fauth", configDat)

			if len(args) != 1 {
				fmt.Println("Wrong arguments! Please check usage with: 2fauth set -h")
				return
			}
			delete(configDat, args[0])
		},
	}

	var rootCmd = &cobra.Command{Use: "2fauth"}
	rootCmd.AddCommand(cmdList, cmdGet, cmdSet, cmdDelete)
	rootCmd.Execute()
}
