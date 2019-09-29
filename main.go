package main

import (
	"encoding/csv"
	"fmt"
	"github.com/dspinhirne/netaddr-go"
	"github.com/gin-gonic/gin"
	"go-nsqauthd/orm"
	"net/http"
	"os"
	"strings"
)

const TTL = 60 * 60

var filePath string = "./auth.csv"
var Accounts []orm.Account

func main() {
	csvFile, err := os.Open(filePath)
	if err != nil {
		panic(err)
	}
	defer csvFile.Close()

	csvReader := csv.NewReader(csvFile)
	rows, err := csvReader.ReadAll()
	headers := []string{"login", "ip", "tls_required", "topic", "channel", "subscribe", "publish"}

	Accounts = make([]orm.Account, 0)
	for i, row := range rows {
		if i == 0 {
			continue
		}
		temp := make(map[string]string)
		fmt.Println(len(row))
		fmt.Println(row)
		for j := 0; j < len(headers); j++ {
			temp[headers[j]] = row[j]
		}
		var account orm.Account
		account.Login = temp["login"]
		if len(temp["ip"]) <= 0 {
			account.IpSet = nil
		} else {
			net, _ := netaddr.ParseIPv4Net(temp["ip"])
			account.IpSet = net
		}
		account.TlsRequired = parseBool(temp["tls_required"])
		account.Topic = temp["topic"]
		account.Channel = temp["channel"]
		account.Permissions = make([]string, 0)
		if len(strings.TrimSpace(temp["subscribe"])) > 0 {
			account.Permissions = append(account.Permissions, "subscribe")
		}
		if len(strings.TrimSpace(temp["publish"])) > 0 {
			account.Permissions = append(account.Permissions, "publish")
		}
		Accounts = append(Accounts, account)
	}

	// 启动web服务
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	// /auth?remote_ip=...&tls=...&auth_secret=...
	r.GET("/auth", auth)
	r.Run(":4181")
}

func parseBool(str string) bool {
	if strings.ToLower(str) == "true" {
		return true
	} else {
		return false
	}
}

func auth(c *gin.Context) {
	// match
	secret, secretOK := c.GetQuery("secret")
	remoteIP, remoteIpOK := c.GetQuery("remote_ip")
	tls, tlsOK := c.GetQuery("tls")

	var resp orm.Resp
	resp.Identity = secret
	resp.TTL = TTL
	resp.Authorizations = make([]*orm.AuthAccount, 0)

	for _, account := range Accounts {
		fmt.Println(account)
		if !secretOK || account.Login != secret {
			continue
		}
		rip, err := netaddr.ParseIPv4(remoteIP)
		if !remoteIpOK || err != nil || (account.IpSet != nil && !account.IpSet.Contains(rip)) {
			continue
		}
		if !tlsOK || parseBool(tls) != account.TlsRequired {
			continue
		}

		resp.Authorizations = append(resp.Authorizations, account.ToAuthAccount())
	}
	if len(resp.Authorizations) <= 0 {
		c.JSON(http.StatusForbidden, gin.H{
			"message": "NOT_AUTHORIZED",
		})
		return
	}
	c.JSON(http.StatusOK, resp)
}
