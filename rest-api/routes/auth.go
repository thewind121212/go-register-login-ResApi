package routes

import (
	"encoding/json"
	"errors"
	"github.com/gorilla/mux"
	"linhdevtran99/rest-api/models"
	"linhdevtran99/rest-api/rest-api/services"
	"linhdevtran99/rest-api/utils"
	"net/http"
)

func RegisterNewAccount(w http.ResponseWriter, r *http.Request) error {
	client := utils.MongoDB
	if r.Method == http.MethodPost {
		var registerInfo models.CreateUser

		_ = json.NewDecoder(r.Body).Decode(&registerInfo)
		//call function check info user type in
		validRegisterInfo := services.CheckAndValidRegisterFiled(&registerInfo, w)
		//call function check data user use in past or not
		isValidData := services.CheckAccountExist(client, registerInfo.Username, registerInfo.Email, w)

		if isValidData == false || validRegisterInfo == false {
			return errors.New("USER DON'T HAVE VALID INFO FOR REGISTER ACCOUNT")
		}

	}
	return nil
}

func AuthRouterSetup(router *mux.Router) {
	authRouter := router.PathPrefix("/account").Subrouter()
	authRouter.Handle("/register", utils.MakeHTTPHandlerFn(RegisterNewAccount)).Methods("POST")
}
