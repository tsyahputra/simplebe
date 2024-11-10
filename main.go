package main

import (
	"github.com/tsyahputra/simplebe/controller"
	"github.com/tsyahputra/simplebe/model"
)

func main() {
	model.ConnectDatabase()
	controller.FirebaseInit()
	controller.AppInitialize()
}
