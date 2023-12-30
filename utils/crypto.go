package utils

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
	"linhdevtran99/rest-api/models"
	"net/http"
	"os"
	"strings"
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

func buildTokenLink(token string, w http.ResponseWriter) (string, string) {
	tokenCustomTrim := strings.ReplaceAll(token, ".", "&")
	emailVerifyLink := "https://api.wliafdew.dev/?p=" + tokenCustomTrim
	png, err := qrcode.Encode(emailVerifyLink, qrcode.Low, 200)
	if err != nil {
		fmt.Println("Internal log: error create qr ")
		_ = WriteJSONInternalError(w, "error create QR code")
	}
	base64Image := base64.StdEncoding.EncodeToString(png)

	return emailVerifyLink, base64Image
}

func EncryptAESMailLink(registerInfo *models.PreusersMongo, w http.ResponseWriter, mailChan chan models.MailVefiry, wg *sync.WaitGroup) chan models.MailVefiry {
	claims := MyCustomClaims{
		registerInfo.Email,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "totodayShop",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["purpose"] = "Email_Verify"

	tokenString, err := token.SignedString([]byte(serect))
	if err != nil {
		fmt.Println("Internal Log: Error signed token fail", err.Error())
		_ = WriteJSONInternalError(w, "Error signing token fail")
	}

	linkMail, imageB64 := buildTokenLink(tokenString, w)

	data := models.MailVefiry{
		LinkMail:    linkMail,
		ImageBase64: imageB64,
	}

	mailChan <- data

	wg.Done()
	return mailChan

}

//
//func DecryptAESMailLink(data string, key string) string {
//}

//OTP+++++++++++++OTP//

func GenOTP(registerInfo *models.PreusersMongo, counter uint64, otpDigits int, w http.ResponseWriter, otpChan chan models.OtpGenerate, wg *sync.WaitGroup) chan models.OtpGenerate {

	serectBase32 := base32.StdEncoding.EncodeToString([]byte(serect + registerInfo.Username + registerInfo.Email))
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
