package main

import (
	"github.com/tsyahputra/simplebe/controller"
	"github.com/tsyahputra/simplebe/helper"
	"github.com/tsyahputra/simplebe/model"
)

func main() {
	model.ConnectDatabase()
	controller.FirebaseInit()
	helper.RedisConnect()
	helper.SMTPConnect()
	controller.AppInitialize()
}
