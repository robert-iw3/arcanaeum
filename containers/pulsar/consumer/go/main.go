package main

import (
	"context"
	"fmt"
	"github.com/apache/pulsar-client-go/pulsar"
	"log"
)

func main() {
    client, err := pulsar.NewClient(pulsar.ClientOptions{
        URL:               "${brokerServiceURL}",
        Authentication:    pulsar.NewAuthenticationToken("${apikey}"),
    })

    if err != nil {
        log.Fatalf("Could not instantiate Pulsar client: %v", err)
    }

    defer client.Close()

    consumer, err := client.Subscribe(pulsar.ConsumerOptions{
        Topic:            "persistent://${tenant}/${namespace}/${topic}",
        SubscriptionName: "${subscription}",
        SubscriptionInitialPosition: pulsar.SubscriptionPositionEarliest,
    })

    if err != nil {
        log.Fatal(err)
    }

    defer consumer.Close()

    for i := 0; i < 10; i++ {
        msg, err := consumer.Receive(context.Background())
        if err != nil {
            log.Fatal(err)
        }

        fmt.Printf("Received message msgId: %v -- content: '%s'\n",
            msg.ID(), string(msg.Payload()))

        consumer.Ack(msg)
    }

    if err := consumer.Unsubscribe(); err != nil {
        log.Fatal(err)
    }
}