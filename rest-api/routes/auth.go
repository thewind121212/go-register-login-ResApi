package routes

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"linhdevtran99/rest-api/models"
	"linhdevtran99/rest-api/rest-api/services"
	"linhdevtran99/rest-api/utils"
	"net/http"
	"time"
)

func RegisterNewAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == http.MethodPost {
		var registerInfo models.CreateUser

		_ = json.NewDecoder(r.Body).Decode(&registerInfo)
		//[ok]

		//call function check info user type in
		validRegisterInfo, responseAPI := services.CheckAndValidRegisterFiled(&registerInfo)
		//[fairy ok]

		if responseAPI != nil {
			return utils.WriteJSON(w, responseAPI.Code, responseAPI.Err)
		}

		fmt.Println(validRegisterInfo)

		//call function check data user use in past or not

		isValidData, responseAPI := services.CheckAccountValid(registerInfo.Username, registerInfo.Email)

		fmt.Println(isValidData)

		if isValidData != true {
			return utils.WriteJSON(w, responseAPI.Code, responseAPI.Err)
		}

		preUserData := &models.PreusersMongo{
			Username:        registerInfo.Username,
			Email:           registerInfo.Email,
			PhoneNumber:     registerInfo.PhoneNumber,
			HashPassword:    registerInfo.Password,
			UUID:            registerInfo.UUID,
			CreatedDate:     time.Now(),
			UpdateDate:      time.Now(),
			VerifySentCount: 1,
		}

		services.GenerateVerifyAccount(preUserData, w)

		//debug
		//if isValidData == true || validRegisterInfo == true {
		//	return utils.WriteJSON(w, http.StatusOK, "USER HAVE VALID INFO FOR REGISTER ACCOUNT")
		//}
		//debug

	}
	return nil
}

func VerifyWithOTP(w http.ResponseWriter, r *http.Request) error {

	if r.Method == http.MethodPost {
		// declare variable
		var otpInfo models.OTPVerify
		//get data from body
		_ = json.NewDecoder(r.Body).Decode(&otpInfo)
		//check otp and create user
		services.CheckOTPIsValid(&otpInfo, w)

	}
	return nil
}

func AuthRouterSetup(router *mux.Router) {
	authRouter := router.PathPrefix("/account").Subrouter()
	authRouter.Handle("/register", utils.MakeHTTPHandlerFn(RegisterNewAccount)).Methods("POST")
	authRouter.Handle("/register/verifyAccountOTP", utils.MakeHTTPHandlerFn(VerifyWithOTP)).Methods("POST")
}
