package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email      string
	TelegramID int64 `gorm:"uniqueIndex"`
	FirstName  string
	LastName   string
	Username   string
	PhotoURL   string
}

type Token struct {
	gorm.Model
	TokenString string `gorm:"uniqueIndex"`
	UserID      uint
	User        User
}

type Domain struct {
	gorm.Model
	Name   string `gorm:"uniqueIndex"`
	UserID uint
	User   User
}
