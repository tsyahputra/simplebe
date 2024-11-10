package controller

import (
	"context"
	"log"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"google.golang.org/api/option"
)

var FCMClient *messaging.Client

func FirebaseInit() {
	// create at https://console.firebase.google.com/
	opt := option.WithCredentialsFile("config/simple-d923a-a28f0d64a893.json")
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatal(err)
	}
	fcmClient, err := app.Messaging(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	FCMClient = fcmClient
}

func SendMultiNotification(deviceTokens []string, judul string, pesan string) error {
	response, err := FCMClient.SendEachForMulticast(context.Background(), &messaging.MulticastMessage{
		Notification: &messaging.Notification{
			Title: judul,
			Body:  pesan,
		},
		Tokens: deviceTokens,
	})
	if response.FailureCount > 1 || err != nil {
		return err
	}
	return nil
}

func SendNotification(deviceToken string, judul string, pesan string) error {
	_, err := FCMClient.Send(context.Background(), &messaging.Message{
		Notification: &messaging.Notification{
			Title: judul,
			Body:  pesan,
		},
		Token: deviceToken,
	})
	if err != nil {
		return err
	}
	return nil
}
