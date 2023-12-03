package rest_api

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"linhdevtran99/rest-api/models"
	"linhdevtran99/rest-api/utils"
	"log"
	"net/http"
	"os"
)

type APIServer struct {
	listenAddr string
}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

type ApiError struct {
	Error string
}

// define function apiFn
type apiFunc func(http.ResponseWriter, *http.Request) error

// makeHTTPHandlerFn fn
func makeHTTPHandlerFn(fn apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			if err := WriteJSON(w, http.StatusInternalServerError, ApiError{Error: err.Error()}); err != nil {
				fmt.Print(err)
			}
		}
	}
}

func NewAPIServer(listenAddr string) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
	}
}

func startMuxServer(s *APIServer, router *mux.Router) {
	log.Println("Listening on", s.listenAddr)

	if err := http.ListenAndServe(s.listenAddr, router); err != nil {
		log.Fatal(err)
	}
}

func (s *APIServer) Run() {
	router := mux.NewRouter()

	router.HandleFunc("/account/register", makeHTTPHandlerFn(s.registerNewAccount))
	router.HandleFunc("/account", makeHTTPHandlerFn(s.handleAccount))
	router.HandleFunc("/test", makeHTTPHandlerFn(s.testCheckUserAndPass))

	startMuxServer(s, router)
}

func (s *APIServer) registerNewAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == http.MethodGet {
		fmt.Println("API Route Healthy")
	}

	return nil
}

func (s *APIServer) testCheckUserAndPass(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	client := utils.MongoDB

	if r.Method == http.MethodGet {
		fmt.Println("hit")

		//m := mail.NewMessage()
		//
		//emailBody := utils.BuildEmail()
		//m.SetHeader("From", "kotomi.poro1@gmail.com")
		//m.SetHeader("To", "nhocdl.poro1@gmail.com")
		//m.SetHeader("Subject", "Hello!")
		//m.SetBody("text/html", emailBody)
		//
		//d := mail.NewDialer("smtp.gmail.com", 587, "kotomi.poro1@gmail.com", "btmpjudzebyspfxw")
		//d.StartTLSPolicy = mail.MandatoryStartTLS
		//
		//// Send the email to Bob, Cora and Dan.
		//if err := d.DialAndSend(m); err != nil {
		//	panic(err)
		//}

		serect := os.Getenv("EMAIL_VERIFY_SECRET")
		//isPass, _ := generatorOtp("hello", "nhocdl.poro1@gmail.com", 12, serect)
		//fmt.Println(isPass)
		cipherBase64 := createLinkVerify(&models.CreateUser{
			Username:        "thewind121212",
			Email:           "nhocdl.poro1@gmail.com",
			Password:        "linhporoQ1@",
			ConfirmPassword: "linhporoQ1@",
		}, serect)

		key := []byte(serect)

		i, err := decrypt(cipherBase64, key)
		if err != nil {
			return err
		}

		fmt.Println(string(i))

	}

	if r.Method == http.MethodPost {
		var registerInfo models.CreateUser

		_ = json.NewDecoder(r.Body).Decode(&registerInfo)
		//call function check info user type in
		validRegisterInfo := checkAndValidDataFiled(&registerInfo, w)
		//call function check data user use in past or not
		isValidData := checkAccountExist(client, registerInfo.Username, registerInfo.Email, w)

		if isValidData == false || validRegisterInfo == false {
			return errors.New("USER DON'T HAVE VALID INFO FOR REGISTER ACCOUNT")
		}

	}

	return nil
}

func (s *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == http.MethodGet {
		ctx := context.Background()

		res, err := utils.Redis.Ping(ctx).Result()

		if err != nil {
			fmt.Println(err)
		}

		fmt.Println(res)

	}
	if r.Method == http.MethodPost {
		fmt.Println("POST")
	}
	if r.Method == http.MethodDelete {
		fmt.Println("DELETE")
	}
	if r.Method == http.MethodPut {
		fmt.Println("PUT")
	}
	if r.Method == http.MethodPatch {
		fmt.Println("PATCH")
	}

	return nil
}

//register group-func

//checking is user create that have account before

func checkAndValidDataFiled(registerData *models.CreateUser, w http.ResponseWriter) bool {
	_ = models.Validate.RegisterValidation("customPassword", models.PasswordValidator)
	errs := models.Validate.Struct(registerData)
	var errStack []string
	if errs != nil {
		for _, err := range errs.(validator.ValidationErrors) {
			switch err.Field() {
			case "Email":
				{
					fmt.Println("Email không hợp lệ")
					errStack = append(errStack, "Email")
				}
			case "Username":
				{
					fmt.Println("User không hợp lệ")
					errStack = append(errStack, "User")
				}
			case "Password":
				{
					fmt.Println("Password không hợp lệ")
					errStack = append(errStack, "Password")
				}
			case "ConfirmPassword":
				{
					fmt.Println("Nhập lại mật khẩu sai")
					errStack = append(errStack, "ConfirmPassword")
				}
			case "PhoneNumber":
				{
					fmt.Println("SĐT không hợp lệ")
					errStack = append(errStack, "PhoneNumber")
				}
			}
		}
		//handle repose error
		w.WriteHeader(http.StatusBadRequest)
		err := json.NewEncoder(w).Encode(errStack)

		if err != nil {
			fmt.Println("There is error in write reponse at checking info user")
		}
		return false
	}

	return true

}

func checkAccountExist(mongoClient *mongo.Client, userName string, email string, w http.ResponseWriter) bool {
	//filter in mongodb
	var isValid bool

	filter := bson.D{
		{"$or", bson.A{
			bson.D{{"username", userName}},
			bson.D{{"email", email}},
		}},
	}

	userData := mongoClient.Database("Totoday-shop").Collection("users")

	var result models.UsersMongo
	err := userData.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		isValid = true
	}
	if err == nil {
		fmt.Println("Email or username already had register")
		w.WriteHeader(http.StatusBadRequest)
		err := json.NewEncoder(w).Encode("Your username or email had been register before")
		if err != nil {
			fmt.Println("There is error in write reponse at checking data user register")
		}
		isValid = false
	}

	return isValid
}

//after cheking register data generate otp and send email write valid time to confirm in redis
// noice this will do concurency for speed reason

type otpGenerate struct {
	pureOTP string
	hashOTP string
}

func generatorOtp(userName string, email string, counter uint64, serect string) (bool, *otpGenerate) {

	serectBase32 := base32.StdEncoding.EncodeToString([]byte(serect + userName + email))
	passCode, err := hotp.GenerateCodeCustom(serectBase32, counter, hotp.ValidateOpts{
		Digits:    6,
		Algorithm: otp.AlgorithmSHA256,
	})

	if err != nil {
		fmt.Println("Fail to create OTP")
		return false, &otpGenerate{
			pureOTP: "none",
			hashOTP: "none",
		}
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(passCode), 5)
	if err != nil {
		fmt.Println("Fail to create OTP")
		return false, &otpGenerate{
			pureOTP: "none",
			hashOTP: "none",
		}
	}

	return true, &otpGenerate{
		pureOTP: passCode,
		hashOTP: string(hashed),
	}
}

func createLinkVerify(registerInfo *models.CreateUser, secrect string) string {

	data, _ := json.Marshal(registerInfo)
	key := []byte(secrect)

	ciphertext, _ := encrypt(data, key)

	cipherTextBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	return cipherTextBase64
}

func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate a random IV (Initialization Vector)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		fmt.Println("error generating IV:", err)
	}

	// Pad the data to a multiple of the block size
	data = pkcs7Pad(data, aes.BlockSize)

	// Create a CBC mode cipher block
	mode := cipher.NewCBCEncrypter(block, iv)

	// Encrypt the data
	ciphertext := make([]byte, len(data))
	mode.CryptBlocks(ciphertext, data)

	// Prepend the IV to the ciphertext
	ciphertext = append(iv, ciphertext...)

	return ciphertext, nil
}

func decrypt(base64Ciphertext string, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(base64Ciphertext)
	if err != nil {
		fmt.Println("error decoding base64:", err)
	}

	// Extract the IV from the ciphertext
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Create a CBC mode cipher block
	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt the data
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove padding
	ciphertext = pkcs7Unpad(ciphertext)

	return ciphertext, nil
}

// pkcs7Pad pads the input to a multiple of blockSize using PKCS#7 padding
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7Unpad removes PKCS#7 padding from the input
func pkcs7Unpad(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}
