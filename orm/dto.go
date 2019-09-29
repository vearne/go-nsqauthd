package orm

import "github.com/dspinhirne/netaddr-go"

type Account struct {
	Login       string
	IpSet       *netaddr.IPv4Net
	TlsRequired bool
	Topic       string
	Channel     string
	Permissions []string
}

func (a *Account) ToAuthAccount() *AuthAccount {
	var authAccount AuthAccount
	authAccount.Permissions = a.Permissions
	authAccount.Topic = a.Topic
	authAccount.Channels = []string{a.Channel}
	return &authAccount
}

type AuthAccount struct {
	Channels    []string `json:"channels"`
	Topic       string   `json:"topic"`
	Permissions []string `json:"permissions"`
}

type Resp struct {
	Identity       string `json:"identity"`
	TTL            int    `json:"ttl"`
	Authorizations []*AuthAccount
}
