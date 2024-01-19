package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-mail/mail"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
	"linhdevtran99/rest-api/models"
	"linhdevtran99/rest-api/utils"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// CheckAndValidRegisterFiled Check the user register field is valid or not
func CheckAndValidRegisterFiled(registerData *models.CreateUser) (bool, *models.ResponseError) {
	_ = models.Validate.RegisterValidation("customPassword", models.PasswordValidator)
	errs := models.Validate.Struct(registerData)
	type errStack []string
	errorAPI := models.ErrorAPI{
		Errors:  make([]string, 0),
		Message: "Error in input data please check again",
		Type:    "InvalidInput",
	}
	if errs != nil {
		for _, err := range errs.(validator.ValidationErrors) {
			switch err.Field() {
			case "Email":
				{
					fmt.Println("Internal Log: Email không hợp lệ")
					errorAPI.Errors = append(errorAPI.Errors, "Email")
				}
			case "Username":
				{
					fmt.Println("Internal Log: User không hợp lệ")
					errorAPI.Errors = append(errorAPI.Errors, "User")
				}
			case "Password":
				{
					fmt.Println("Internal Log: Password không hợp lệ")
					errorAPI.Errors = append(errorAPI.Errors, "Password")
				}
			case "ConfirmPassword":
				{
					fmt.Println("Internal Log: Nhập lại mật khẩu sai")
					errorAPI.Errors = append(errorAPI.Errors, "ConfirmPassword")
				}
			case "PhoneNumber":
				{
					fmt.Println("Internal Log: SĐT không hợp lệ")
					errorAPI.Errors = append(errorAPI.Errors, "PhoneNumber")
				}
			}
		}
		//handle repose error
		return false, &models.ResponseError{Code: http.StatusTooManyRequests, Err: errorAPI}
	}

	return true, nil

}

// CheckAccountExist Checking in db is user input same data in
func CheckAccountValid(userName string, email string) (bool, *models.ResponseError) {
	//filter in mongodb
	var isValid bool
	var errAPI *models.ResponseError
	var dataRedisRetrive models.RedisOTP

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
		errAPI = &models.ResponseError{
			Code: http.StatusBadRequest,
			Err: models.ErrorAPI{
				Errors:  []string{"Account existed"},
				Message: "Email or username already had register",
				Type:    "AccountExisted",
			},
		}
	}
	retrievedValue, err := utils.Redis.Get(context.Background(), "otp:"+email).Result()
	err = json.Unmarshal([]byte(retrievedValue), &dataRedisRetrive)
	if err != nil {
		fmt.Println("Internal Log: Can't get data from redis")
	}

	timeDiff := time.Now().Unix() - dataRedisRetrive.CreatedDate

	if timeDiff < 30 {
		isValid = false
		fmt.Println("Internal Log: Rate limit send verify mail")
		errAPI = &models.ResponseError{
			Code: http.StatusBadRequest,
			Err: models.ErrorAPI{
				Errors:  []string{"Rate limit send verify mail"},
				Message: "wait " + strconv.FormatInt(30-timeDiff, 10) + " to send verify mail again",
				Type:    "RateLimit",
			},
		}

	}

	return isValid, errAPI
}

// GeneratorOtp Generate OTP Verify Link and Qr Link

const (
	otpDigits     = 6
	mailValidTime = time.Minute * 15
)

func GenerateVerifyAccount(registerInfo *models.PreusersMongo, w http.ResponseWriter) error {
	var wg sync.WaitGroup

	otpChannel := make(chan models.OtpGenerate, 1)
	mailChannel := make(chan models.MailVefiry, 1)

	counter := CheckAndWritePreuser(registerInfo, w)
	wg.Add(1)
	go utils.GenOTP(registerInfo, counter, otpDigits, w, otpChannel, &wg)
	wg.Add(1)
	go utils.EncryptAESMailLink(registerInfo, w, mailChannel, &wg)
	go createMailVerify(registerInfo, otpChannel, mailChannel, w)
	go writeOTPInRedis(counter, registerInfo, otpChannel, w)

	wg.Wait()
	err := utils.WriteJSON(w, http.StatusOK, models.SuccessAPI{
		Message: "Success register account please verify your account",
	})
	return err

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

	m.SetHeader("From", "admin@wliafdew.dev")
	m.SetHeader("To", registerInfo.Email)
	m.SetHeader("Subject", "Thanks For Join My Business")
	m.SetBody("text/html", emailBody)
	m.Embed("./temp/" + qrFileName)

	d := mail.NewDialer("mail.wliafdew.dev", 465, "admin@wliafdew.dev", smtpPass)
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

func writeOTPInRedis(counter uint64, registerInfo *models.PreusersMongo, otpChan chan models.OtpGenerate, w http.ResponseWriter) {

	otp := <-otpChan

	dataRedis := &models.RedisOTP{
		Email:       registerInfo.Email,
		User:        registerInfo.Username,
		CreatedDate: registerInfo.CreatedDate.Unix(),
		HashOTP:     otp.HashOTP,
		Counter:     counter,
	}

	jsonData, err := json.Marshal(dataRedis)
	if err != nil {
		fmt.Println("Internal log: Can't stringfy json data")
		_ = utils.WriteJSONInternalError(w, "Can't stringfy json data")
	}
	status := utils.Redis.Set(context.Background(), "otp:"+registerInfo.Email, string(jsonData), time.Hour*24)

	fmt.Println(status.Err())

}

// ////////////////////////Create User Complete//////////////////////////
func CreateUserAfterVerify(otpInfo *models.OTPVerify, redis *models.RedisOTP, w http.ResponseWriter) bool {
	isValid := true
	var preUserData models.PreusersMongo
	filter := bson.D{{"email", otpInfo.Email}}
	err := utils.PreUserData.FindOne(context.Background(), filter).Decode(&preUserData)

	if err != nil {
		fmt.Println("Internal log: Can't get preuser data")
		//_ = utils.WriteJSONInternalError(w, "Please register again")
		isValid = false
	}

	user := models.UsersMongo{
		Username:        preUserData.Username,
		Email:           preUserData.Email,
		PhoneNumber:     preUserData.PhoneNumber,
		HashPassword:    preUserData.HashPassword,
		Active:          true,
		CreatedDate:     time.Now(),
		UpdateDate:      time.Now(),
		VerifySentCount: int(redis.Counter),
	}

	_, err = utils.User.InsertOne(context.Background(), user)

	if err != nil {
		fmt.Println("Internal log: Can't insert user data")
		//_ = utils.WriteJSONInternalError(w, "Can't insert user data")
		isValid = false
	}

	if isValid == true {
		fmt.Println("Internal log: Success verify account")
		_ = utils.WriteJSON(w, http.StatusOK, models.SuccessAPI{
			Message: "Success verify account",
			Type:    "SuccessVerify",
		})
	}

	return isValid

}

//////////////////////////Verify OTP//////////////////////////

func CheckUserVerify(otpInfo *models.OTPVerify, w http.ResponseWriter) bool {
	isVerified := false
	filter := bson.D{{"email", otpInfo.Email}}
	var user models.UsersMongo
	_ = utils.User.FindOne(context.Background(), filter).Decode(&user)

	if user.Active == true {
		fmt.Println("Internal log: Account already verify")
		_ = utils.WriteJSON(w, http.StatusBadRequest, models.ErrorAPI{
			Errors:  []string{"Account already verify"},
			Message: "Account already verify",
			Type:    "AccountAlreadyVerify",
		})
		isVerified = true
	}

	return isVerified

}

func CheckOTPIsValid(otpInfo *models.OTPVerify, w http.ResponseWriter) bool {
	var isValid bool
	isValid = true
	//get data from redis
	var dataRedis models.RedisOTP
	//verify uuid and email
	value, err := utils.Redis.Get(context.Background(), "otp:"+otpInfo.Email).Result()
	if err != nil {
		fmt.Println("Internal log: Email not valid")
		_ = utils.WriteJSON(w, http.StatusBadRequest, models.ErrorAPI{
			Errors:  []string{"Email not valid"},
			Message: "Email not valid",
			Type:    "EmailNotValid",
		})
		isValid = false
		return false
	}

	_ = json.Unmarshal([]byte(value), &dataRedis)
	_, err = uuid.Parse(otpInfo.UUID)
	if err != nil {
		fmt.Println("Internal log: UUID not valid")
		_ = utils.WriteJSON(w, http.StatusBadRequest, models.ErrorAPI{
			Errors:  []string{"UUID not valid"},
			Message: "UUID not valid",
			Type:    "UUIDNotValid",
		})
		isValid = false
	}

	if isVerified := CheckUserVerify(otpInfo, w); isVerified == true {
		return false
	}

	isValid = utils.VerifyOTP(otpInfo, dataRedis, w)

	if isValid == true {
		CreateUserAfterVerify(otpInfo, &dataRedis, w)
	}
	return true
}
