package utils

import (
	"bytes"
	"fmt"
	"html/template"
	"linhdevtran99/rest-api/models"
)

func BuildEmail(otp string, mailLink string, fileName string) string {

	qrcodeURL := template.URL("cid:" + fileName)

	data := models.EmailTemplate{
		Otp:             otp,
		AlternativeLink: mailLink,
		QrCode:          qrcodeURL,
	}

	//tmpl, err := template.ParseFiles("./Template/email.html")
	tmpl, err := template.ParseFiles("./Template/email.html")

	if err != nil {
		fmt.Println("Cant achieve file")
	}

	var result bytes.Buffer
	_ = tmpl.Execute(&result, data)

	return result.String()

}
