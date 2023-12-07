package models

import (
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"html/template"
	"strings"
	"time"
	"unicode"
)

// Mongodb Type
type PreusersMongo struct {
	ID              primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Username        string             `bson:"username" json:"username" `
	Email           string             `bson:"email" json:"email"`
	HashPassword    string             `bson:"hash_password" json:"hash_password"`
	PhoneNumber     string             `bson:"phone_number" json:"phone_number"`
	CreatedDate     time.Time          `bson:"created_date" json:"created_date"`
	UpdateDate      time.Time          `bson:"update_date" json:"update_date"`
	VerifySentCount int                `bson:"verify_sent_count" json:"verify_sent_count"`
}

type UsersMongo struct {
	ID              primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Username        string             `bson:"username" json:"username"`
	Email           string             `bson:"email" json:"email"`
	HashPassword    string             `bson:"hash_password" json:"hash_password"`
	PhoneNumber     string             `bson:"phone_number" json:"phone_number"`
	Active          bool               `bson:"active" json:"active"`
	CreatedDate     time.Time          `bson:"created_date" json:"created_date"`
	UpdateDate      time.Time          `bson:"update_date" json:"update_date"`
	VerifySentCount int                `bson:"verify_sent_count" json:"verify_sent_count"`
}

var Validate *validator.Validate

// API Type
type CreateUser struct {
	Username        string `json:"username" validate:"required,min=8,max=20"`
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,min=8,max=20,customPassword"`
	ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=Password"`
	PhoneNumber     string `json:"phone_number" validate:"required,len=10"`
}

type Users struct {
	Username     string `json:"username"`
	Email        string `json:"email"`
	HashPassword string `json:"hash_password"`
	PhoneNumber  string `json:"phone_number"`
	Active       bool   `json:"active"`
	CreatedDate  string `json:"created_date"`
	ValidDate    int    `json:"verify_sent_count"`
}

// custom validator list

func PasswordValidator(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	// Flags to track if at least one symbol and one number are found
	hasSymbol := false
	hasNumber := false

	// Check if the password contains at least one symbol and one number
	for _, char := range password {
		if strings.ContainsRune("!@#$%^&*()-_=+[]{}|;:'\"<>,.?/~`", char) {
			hasSymbol = true
		} else if unicode.IsNumber(char) {
			hasNumber = true
		}

		// Break early if both conditions are met
		if hasSymbol && hasNumber {
			return true
		}
	}

	return false
}

//Interal Type

type OtpGenerate struct {
	PureOTP string
	HashOTP string
}

type MailVefiry struct {
	LinkMail    string
	ImageBase64 string
}

type EmailTemplate struct {
	Otp             string `json:"otp"`
	AlternativeLink string `json:"alternativeLink"`
	QrCode          template.URL
}
