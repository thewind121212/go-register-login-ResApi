package services

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"linhdevtran99/rest-api/models"
	"linhdevtran99/rest-api/utils"
	"net/http"
)

// Check the user register field is valid or not
func CheckAndValidRegisterFiled(registerData *models.CreateUser, w http.ResponseWriter) bool {
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

// Checking in db is user input same data in
func CheckAccountExist(mongoClient *mongo.Client, userName string, email string, w http.ResponseWriter) bool {
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

// Generate HOtp for confirm infomation
func GeneratorOtp(userName string, email string, counter uint64, serect string) (bool, *models.OtpGenerate) {

	serectBase32 := base32.StdEncoding.EncodeToString([]byte(serect + userName + email))
	passCode, err := hotp.GenerateCodeCustom(serectBase32, counter, hotp.ValidateOpts{
		Digits:    6,
		Algorithm: otp.AlgorithmSHA256,
	})

	if err != nil {
		fmt.Println("Fail to create OTP")
		return false, &models.OtpGenerate{
			PureOTP: "none",
			HashOTP: "none",
		}
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(passCode), 5)
	if err != nil {
		fmt.Println("Fail to create OTP")
		return false, &models.OtpGenerate{
			PureOTP: "none",
			HashOTP: "none",
		}
	}

	return true, &models.OtpGenerate{
		PureOTP: passCode,
		HashOTP: string(hashed),
	}
}

// Create a alternative verify link
func CreateLinkVerify(registerInfo *models.CreateUser, secrect string) string {

	data, _ := json.Marshal(registerInfo)
	key := []byte(secrect)

	ciphertext, _ := utils.EncryptAES(data, key)

	cipherTextBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	return cipherTextBase64
}
