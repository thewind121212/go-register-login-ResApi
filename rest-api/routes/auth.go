package routes

import (
	"encoding/json"
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
		//call function check info user type in
		validRegisterInfo, responseAPI := services.CheckAndValidRegisterFiled(&registerInfo)
		if responseAPI != nil {
			return utils.WriteJSON(w, responseAPI.Code, responseAPI.Err.Error())
		}
		//call function check data user use in past or not
		isValidData, responseAPI := services.CheckAccountExist(registerInfo.Username, registerInfo.Email)
		if responseAPI != nil {
			return utils.WriteJSON(w, responseAPI.Code, responseAPI.Err.Error())
		}

		preUserData := &models.PreusersMongo{
			Username:        registerInfo.Username,
			Email:           registerInfo.Email,
			PhoneNumber:     registerInfo.PhoneNumber,
			HashPassword:    registerInfo.Password,
			CreatedDate:     time.Now(),
			UpdateDate:      time.Now(),
			VerifySentCount: 1,
		}

		services.GenerateVerifyAccount(preUserData, w)

		//debug
		if isValidData == true || validRegisterInfo == true {
			return utils.WriteJSON(w, http.StatusOK, "USER HAVE VALID INFO FOR REGISTER ACCOUNT")
		}
		//debug

	}
	return nil
}

func AuthRouterSetup(router *mux.Router) {
	authRouter := router.PathPrefix("/account").Subrouter()
	authRouter.Handle("/register", utils.MakeHTTPHandlerFn(RegisterNewAccount)).Methods("POST")
}
