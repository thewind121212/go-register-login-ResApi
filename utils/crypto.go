package utils

import (
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/skip2/go-qrcode"
	"net/http"
	"strings"
	"time"
)

//Mail

type MyCustomClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func buildTokenLink(token string, w http.ResponseWriter) (string, string) {
	tokenCustomTrim := strings.ReplaceAll(token, ".", "&")
	emailVerifyLink := "http://www.totoday.com/?p=" + tokenCustomTrim
	fmt.Println(emailVerifyLink)
	png, err := qrcode.Encode(emailVerifyLink, qrcode.Low, 200)
	if err != nil {
		fmt.Println("Internal log: error create qr ")
		_ = WriteJSONInternalError(w, "error create QR code")
	}
	base64Image := base64.StdEncoding.EncodeToString(png)
	dataURL := "data:image/png;base64," + base64Image

	return emailVerifyLink, dataURL
}

func EncryptAESMailLink(data string, key string, w http.ResponseWriter) (string, string) {
	claims := MyCustomClaims{
		data,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "totodayShop",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["purpose"] = "Email_Verify"

	tokenString, err := token.SignedString([]byte(key))
	if err != nil {
		fmt.Println("Internal Log: Error signed token fail", err.Error())
		_ = WriteJSONInternalError(w, "Error signing token fail")
	}

	return buildTokenLink(tokenString, w)
}

//
//func DecryptAESMailLink(data string, key string) string {
//}

//OTP
//Write preuser to mongo db

//func WriteToMongo(registerInfo *models.PreusersMongo) {
//
//
//}

//Write otp to redis

//func CheckAndWriteRedis(email string, username string, hashOTP string) {
//	//checking does it valid or have in redis or not
//	//var count int
//	exists, err := Redis.Exists(context.Background(), "otp:nhocdl.poro1@gmail.com").Result()
//	if err != nil {
//		fmt.Println("something went wrong")
//	}
//	if exists == 0 {
//		//count = 0
//
//	}
//}
