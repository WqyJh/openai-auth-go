# openai-auth-go

An go library to get openai access token by username (email) and password.

## Usage

Create an auther

```go
auther, err := auth.NewAuthenticator()
```


Or you can create it with proxy

```go
auther, err := auth.NewAuthenticator(auth.WithProxy("socks5://127.0.0.1:7890"))
```

Start authentication and get access_token

```go
cred, err := auther.AuthUser("email@example.com", "passw0rd")
// ...
accessToken := cred.Session.AccessToken
```

## Examples

```go
package main

import (
        "context"
        "fmt"
        "log"

        gogpt "github.com/sashabaranov/go-gpt3"
        auth "github.com/wqyjh/openai-auth-go"
)

func main() {
        auther, err := auth.NewAuthenticator(auth.WithProxy("socks5://192.168.42.1:7890"))
        if err != nil {
                log.Fatalf("%+v\n", err)
        }
        cred, err := auther.AuthUser("email@example.com", "passw0rd")
        if err != nil {
                log.Fatalf("%+v\n", err)
        }
        log.Printf("%+v\n", cred)
        accessToken := cred.Session.AccessToken
        c := gogpt.NewClient(accessToken)

        log.Println("welcome")
        for {
                var prompt string
                fmt.Print("> ")
                fmt.Scanf("%s\n", &prompt)
                ctx := context.Background()
                req := gogpt.ChatCompletionRequest{
                        Model:       gogpt.GPT3Dot5Turbo,
                        MaxTokens:   1000,
                        Temperature: 0,
                        Messages: []gogpt.ChatCompletionMessage{
                                {
                                        Role:    "system",
                                        Content: "you are a translate assistant",
                                },
                                {
                                        Role:    "user",
                                        Content: prompt,
                                },
                        },
                }
                resp, err := c.CreateChatCompletion(ctx, req)
                if err != nil {
                        return
                }
                fmt.Printf("< %+v\n", resp.Choices[0].Message.Content)
        }
}
```
