package utils

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/skip2/go-qrcode"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
	"linhdevtran99/rest-api/models"
	"net/http"
	"os"
	"sync"
	"time"
)

//const

var serect = os.Getenv("EMAIL_VERIFY_SECRET")

//Mail

type MyCustomClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func buildTokenLink(registerInfo *models.PreusersMongo, token string, w http.ResponseWriter) (string, string) {
	emailVerifyLink := "http://localhost:4200/register?uuid=" + registerInfo.UUID + "&register_step=verify_with_jwt" + "&p=" + token
	png, err := qrcode.Encode(emailVerifyLink, qrcode.Low, 200)
	if err != nil {
		fmt.Println("Internal log: error create qr ")
		_ = WriteJSONInternalError(w, "error create QR code")
	}
	base64Image := base64.StdEncoding.EncodeToString(png)

	return emailVerifyLink, base64Image
}

func EncryptAESMailLink(registerInfo *models.PreusersMongo, w http.ResponseWriter, mailChan chan models.MailVefiry, wg *sync.WaitGroup, timeCreate time.Time) chan models.MailVefiry {
	claims := MyCustomClaims{
		registerInfo.Email,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(timeCreate),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "totodayShopRegister",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["purpose"] = "Email_Verify"

	tokenString, err := token.SignedString([]byte(serect + registerInfo.UUID))
	if err != nil {
		fmt.Println("Internal Log: Error signed token fail", err.Error())
		_ = WriteJSONInternalError(w, "Error signing token fail")
	}
	tokenBS64 := base64.StdEncoding.EncodeToString([]byte(tokenString))

	linkMail, imageB64 := buildTokenLink(registerInfo, tokenBS64, w)

	data := models.MailVefiry{
		LinkMail:    linkMail,
		ImageBase64: imageB64,
	}

	mailChan <- data

	wg.Done()
	return mailChan

}

func DecryptAESMailLink(linkVerifyInfo *models.LinkVerify, w http.ResponseWriter) (bool, string) {
	decodeBase64, err := base64.StdEncoding.DecodeString(linkVerifyInfo.JWT)
	token, err := jwt.ParseWithClaims(string(decodeBase64), &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(serect + linkVerifyInfo.UUID), nil
	})
	if err != nil {
		fmt.Println("Internal log: Error decrypt token fail", err.Error())
		if errors.Is(err, jwt.ErrTokenMalformed) {
			_ = WriteJSON(w, http.StatusBadRequest, models.ErrorAPI{
				Errors:  []string{"Token is malformed"},
				Message: "Token is invalid",
				Type:    "TokenMalformed",
			})
		}
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			_ = WriteJSON(w, http.StatusBadRequest, models.ErrorAPI{
				Errors:  []string{"UUID is invalid"},
				Message: "UUID is invalid",
				Type:    "UUIDInvalid",
			})
		}

		if errors.Is(err, jwt.ErrTokenExpired) {
			_ = WriteJSON(w, http.StatusBadRequest, models.ErrorAPI{
				Errors:  []string{"Token is expired"},
				Message: "Link is expired please register again",
				Type:    "TokenExpired",
			})
		}

		return false, ""
	}

	if token.Valid && token.Header["purpose"] == "Email_Verify" && err == nil {
		//get update date from preuser
		var preUser models.PreusersMongo
		email := token.Claims.(*MyCustomClaims).Email
		err := PreUserData.FindOne(context.TODO(), bson.M{"email": email}).Decode(&preUser)
		if err != nil {
			//handler erorr later
			fmt.Println("Internal log: Error find preuser fail", err.Error())
			return false, ""
		}
		timeRegisterToken := preUser.UpdateDate.Unix()
		timeIssueToken, _ := token.Claims.GetIssuedAt()
		if timeRegisterToken != timeIssueToken.Unix() {
			//handler erorr later
			fmt.Println("Internal log: Error token is not valid to use")
			return false, ""
		}
		return true, email
	}

	return false, ""

}

//OTP+++++++++++++OTP//

// Gen Otp and hash otp
func GenOTP(registerInfo *models.PreusersMongo, counter uint64, otpDigits int, w http.ResponseWriter, otpChan chan models.OtpGenerate, wg *sync.WaitGroup) chan models.OtpGenerate {

	serectBase32 := base32.StdEncoding.EncodeToString([]byte(serect + registerInfo.UUID + registerInfo.Email))
	passCode, err := hotp.GenerateCodeCustom(serectBase32, counter, hotp.ValidateOpts{
		Digits:    otp.Digits(otpDigits),
		Algorithm: otp.AlgorithmSHA256,
	})

	if err != nil {
		fmt.Println("Internal log: Fail to create OTP")
		_ = WriteJSONInternalError(w, "Fail to create OTP")
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(passCode), 5)
	if err != nil {
		fmt.Println("Internal log: Fail to encrypt OTP")
		_ = WriteJSONInternalError(w, "Fail to encrypt OTP")
	}

	data := models.OtpGenerate{
		PureOTP: passCode,
		HashOTP: string(hashed),
	}

	otpChan <- data
	otpChan <- data
	wg.Done()
	return otpChan

}

//Decrypt OTP and verify otp

//task
//decrypt hack otp in redis //testing current
//verify otp //testing current
//write preuser to real user db
//reposne and countinue

func VerifyOTP(otpInfo *models.OTPVerify, redisOTP models.RedisOTP, w http.ResponseWriter) bool {
	serectBase32 := base32.StdEncoding.EncodeToString([]byte(serect + otpInfo.UUID + otpInfo.Email))

	isOTPMatch, _ := hotp.ValidateCustom(otpInfo.OTP, redisOTP.Counter, serectBase32, hotp.ValidateOpts{
		Digits:    otp.Digits(6),
		Algorithm: otp.AlgorithmSHA256,
	})

	if isOTPMatch != true {
		fmt.Println("Internal log: OTP is not match")
		_ = WriteJSON(w, http.StatusBadRequest, models.ErrorAPI{
			Errors:  []string{"OTP is not match"},
			Message: "OTP is not match",
			Type:    "OTP",
		})
	}
	fmt.Println("isOTPMatch: ", isOTPMatch)
	return isOTPMatch
}
