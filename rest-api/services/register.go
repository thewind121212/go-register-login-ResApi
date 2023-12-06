package services

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
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
	"time"
)

type ResponseError struct {
	Code int
	Err  error
}

// CheckAndValidRegisterFiled Check the user register field is valid or not
func CheckAndValidRegisterFiled(registerData *models.CreateUser) (bool, *ResponseError) {
	_ = models.Validate.RegisterValidation("customPassword", models.PasswordValidator)
	errs := models.Validate.Struct(registerData)
	var errStack []string
	if errs != nil {
		for _, err := range errs.(validator.ValidationErrors) {
			switch err.Field() {
			case "Email":
				{
					fmt.Println("Internal Log: Email không hợp lệ")
					errStack = append(errStack, "Email")
				}
			case "Username":
				{
					fmt.Println("Internal Log: User không hợp lệ")
					errStack = append(errStack, "User")
				}
			case "Password":
				{
					fmt.Println("Internal Log: Password không hợp lệ")
					errStack = append(errStack, "Password")
				}
			case "ConfirmPassword":
				{
					fmt.Println("Internal Log: Nhập lại mật khẩu sai")
					errStack = append(errStack, "ConfirmPassword")
				}
			case "PhoneNumber":
				{
					fmt.Println("Internal Log: SĐT không hợp lệ")
					errStack = append(errStack, "PhoneNumber")
				}
			}
		}
		//handle repose error
		jsonData, _ := json.Marshal(errStack)
		return false, &ResponseError{Code: http.StatusBadRequest, Err: errors.New(string(jsonData))}
	}

	return true, nil

}

// CheckAccountExist Checking in db is user input same data in
func CheckAccountExist(mongoClient *mongo.Client, userName string, email string) (bool, *ResponseError) {
	//filter in mongodb
	var isValid bool
	var errAPI *ResponseError

	filter := bson.D{
		{"$or", bson.A{
			bson.D{{"username", userName}},
			bson.D{{"email", email}},
		}},
	}

	_, err := utils.PreUserData.FindOne(context.TODO(), filter).Raw()
	if err != nil {
		isValid = true
		errAPI = nil
	} else {
		fmt.Println("Internal Log: Email or username already had register")
		isValid = false
		errAPI = &ResponseError{
			Code: http.StatusBadRequest,
			Err:  errors.New("your username or email had been register before"),
		}
	}

	return isValid, errAPI
}

// GeneratorOtp Generate HOtp for confirm information

func GeneratorOtp(userName string, email string, counter uint64, serect string) (bool, *models.OtpGenerate) {

	serectBase32 := base32.StdEncoding.EncodeToString([]byte(serect + userName + email))
	passCode, err := hotp.GenerateCodeCustom(serectBase32, counter, hotp.ValidateOpts{
		Digits:    6,
		Algorithm: otp.AlgorithmSHA256,
	})

	if err != nil {
		fmt.Println("Fail to create OTP")
		return false, nil
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(passCode), 5)
	if err != nil {
		fmt.Println("Fail to create OTP")
		return false, nil
	}

	return true, &models.OtpGenerate{
		PureOTP: passCode,
		HashOTP: string(hashed),
	}
}

// CreateLinkVerify Create a alternative verify link
func CreateLinkVerify(registerInfo string, secrect string) string {
	return "linh"

}

// check and write pre use into mongo db
func CheckAndWritePreuser(registerInfo *models.PreusersMongo) {
	//checking
	email := registerInfo.Email
	filter := bson.D{{"email", email}}
	_, err := utils.PreUserData.FindOne(context.Background(), filter).Raw()
	if err != nil {
		hashed, err := bcrypt.GenerateFromPassword([]byte(registerInfo.HashPassword), 10)
		if err != nil {
			fmt.Println("Fail to create OTP")
		}
		registerInfo.HashPassword = string(hashed)
		_, err = utils.PreUserData.InsertOne(context.Background(), registerInfo)
		if err != nil {
			fmt.Println("Something Went Wrong")
		}
	} else {
		update := bson.D{
			{"$inc", bson.D{
				{"verify_sent_count", 1},
			}},
			{"$set", bson.D{
				{"update_date", time.Now()},
			},
			}}

		_, err := utils.PreUserData.UpdateOne(context.Background(), filter, update)
		if err != nil {
			fmt.Println("Internal log: update document fail")
		}

	}

}
