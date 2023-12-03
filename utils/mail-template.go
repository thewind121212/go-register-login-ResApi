package utils

import (
	"bytes"
	"fmt"
	"html/template"
	"linhdevtran99/rest-api/models"
)

func BuildEmail() string {

	data := models.EmailTemplate{
		Otp:             "11017",
		AlternativeLink: "https://www.google.com.vn",
	}

	tmpl, err := template.ParseFiles("./Template/email.html")

	if err != nil {
		fmt.Println("Cant achieve file")
	}

	var result bytes.Buffer
	_ = tmpl.Execute(&result, data)

	fmt.Println(result.String())
	return result.String()

}
