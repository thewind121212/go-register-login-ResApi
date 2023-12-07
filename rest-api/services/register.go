package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-mail/mail"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
	"linhdevtran99/rest-api/models"
	"linhdevtran99/rest-api/utils"
	"log"
	"net/http"
	"os"
	"sync"
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
func CheckAccountExist(userName string, email string) (bool, *ResponseError) {
	//filter in mongodb
	var isValid bool
	var errAPI *ResponseError

	filter := bson.D{
		{"$or", bson.A{
			bson.D{{"username", userName}},
			bson.D{{"email", email}},
		}},
	}

	_, err := utils.User.FindOne(context.TODO(), filter).Raw()
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

// GeneratorOtp Generate OTP Verify Link and Qr Link

const (
	otpDigits     = 6
	mailValidTime = time.Hour * 24
)

func GenerateVerifyAccount(registerInfo *models.PreusersMongo, w http.ResponseWriter) {
	var wg sync.WaitGroup

	otpChannel := make(chan models.OtpGenerate, 1)
	mailChannel := make(chan models.MailVefiry, 1)

	counter := CheckAndWritePreuser(registerInfo, w)
	wg.Add(1)
	go utils.GenOTP(registerInfo, counter, otpDigits, w, otpChannel, &wg)
	wg.Add(1)
	go utils.EncryptAESMailLink(registerInfo, w, mailChannel, &wg)
	go createMailVerify(registerInfo, otpChannel, mailChannel, w)
	go writeOTPInRedis(registerInfo, otpChannel, w)

	wg.Wait()

}

// CreateLinkVerify Create a alternative verify link
func createMailVerify(registerInfo *models.PreusersMongo, otpChan chan models.OtpGenerate, mailChan chan models.MailVefiry, w http.ResponseWriter) {
	smtpPass := os.Getenv("SMTP_PASS")
	m := mail.NewMessage()

	opt := <-otpChan
	mailVerify := <-mailChan

	decodedImage, err := base64.StdEncoding.DecodeString(mailVerify.ImageBase64)
	if err != nil {
		log.Println("Error decoding base64 image:", err)
	}

	qrFileName := registerInfo.Email + registerInfo.Username + ".png"
	os.WriteFile("./temp/"+qrFileName, decodedImage, 0666)
	emailBody := utils.BuildEmail(opt.PureOTP, mailVerify.LinkMail, qrFileName)

	m.SetHeader("From", "kotomi.poro1@gmail.com")
	m.SetHeader("To", registerInfo.Email)
	m.SetHeader("Subject", "Thanks For Join My Business")
	m.SetBody("text/html", emailBody)
	m.Embed("./temp/" + qrFileName)

	d := mail.NewDialer("smtp.gmail.com", 587, "kotomi.poro1@gmail.com", smtpPass)
	d.StartTLSPolicy = mail.MandatoryStartTLS

	// Send the email to Bob, Cora and Dan.
	if err := d.DialAndSend(m); err != nil {
		fmt.Println("Internal Log: Fail to send email check smtp")
		_ = utils.WriteJSONInternalError(w, "Fail to send email check smtp")
		panic(err)
	}

	defer func() {
		os.Remove("./temp/" + qrFileName)
	}()
}

// check and write pre use into mongo db
func CheckAndWritePreuser(registerInfo *models.PreusersMongo, w http.ResponseWriter) uint64 {
	//checking
	email := registerInfo.Email
	count := 1
	filter := bson.D{{"email", email}}
	raw, err := utils.PreUserData.FindOne(context.Background(), filter).Raw()
	if err != nil {
		hashed, err := bcrypt.GenerateFromPassword([]byte(registerInfo.HashPassword), 10)
		if err != nil {
			fmt.Println("Internal Log :Fail to create OTP")
			_ = utils.WriteJSONInternalError(w, "Fail to create OTP")
		}
		registerInfo.HashPassword = string(hashed)
		_, err = utils.PreUserData.InsertOne(context.Background(), registerInfo)
		if err != nil {
			fmt.Println("Internal Log: Can't Insert Data To PreUser")
			_ = utils.WriteJSONInternalError(w, "Can't Insert Data To PreUser")
		}
		return uint64(count)
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
			fmt.Println("Internal log: Update document fail")
			_ = utils.WriteJSONInternalError(w, "Update document fail")
		}
		fmt.Println()
		count = int(raw.Lookup("verify_sent_count").Int32() + 1)
		return uint64(count)
	}

}

//write otp in redis for valid if otp expired

func writeOTPInRedis(registerInfo *models.PreusersMongo, otpChan chan models.OtpGenerate, w http.ResponseWriter) {

	otp := <-otpChan

	data := map[string]string{
		"email":       registerInfo.Email,
		"user":        registerInfo.Username,
		"create_date": registerInfo.CreatedDate.String(),
		"hashOTP":     otp.HashOTP,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Internal log: Can't stringfy json data")
		_ = utils.WriteJSONInternalError(w, "Can't stringfy json data")
	}
	status := utils.Redis.Set(context.Background(), "otp:nhocdl.poro1@gmail.com", string(jsonData), time.Minute*2)

	fmt.Println(status.Err())

}
