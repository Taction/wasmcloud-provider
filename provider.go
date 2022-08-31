package provider

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/sirupsen/logrus"
	msgpack "github.com/vmihailenco/msgpack/v5"
)

var log = logrus.New()

func init() {
	os.Setenv("RUST_LOG", "debug")

	file, err := os.OpenFile("/tmp/litestream_wc.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
	} else {
		log.Info("Failed to log to file, using default stderr")
	}

	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetReportCaller(true)
}

type LinkDefinition struct {
	ActorID    string            `msgpack:"actor_id"`
	ProviderID string            `msgpack:"provider_id"`
	LinkName   string            `msgpack:"link_name"`
	ContractID string            `msgpack:"contract_id"`
	Values     map[string]string `msgpack:"values"`
}

type ActorConfig struct {
	ActorID     string
	ActorConfig map[string]string
}

type WasmCloudEntity struct {
	PublicKey  string `msgpack:"public_key"`
	LinkName   string `msgpack:"link_name"`
	ContractID string `msgpack:"contract_id"`
}

type Invocation struct {
	Origin        WasmCloudEntity `msgpack:"origin"`
	Target        WasmCloudEntity `msgpack:"target"`
	Operation     string          `msgpack:"operation"`
	Msg           []byte          `msgpack:"msg"`
	ID            string          `msgpack:"id"`
	EncodedClaims string          `msgpack:"encoded_claims"`
	HostID        string          `msgpack:"host_id"`
}

func (i *Invocation) EncodeClaims(hostData HostData, guid string) error {
	var Ed25519SigningMethod jwt.SigningMethodEd25519
	jwt.RegisterSigningMethod("Ed25519", func() jwt.SigningMethod { return &Ed25519SigningMethod })

	service, err := nkeys.FromSeed([]byte(hostData.InvocationSeed))
	if err != nil {
		return err
	}

	pkey, err := service.PrivateKey()
	if err != nil {
		return err
	}

	pubkey, err := service.PublicKey()
	if err != nil {
		return err
	}

	rKey, err := nkeys.Decode(nkeys.PrefixBytePrivate, pkey)
	if err != nil {
		return err
	}

	claims := Claims{
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			Issuer:   pubkey,
			Subject:  guid,
		},
		ID: guid,
		Wascap: Wascap{
			TargetURL: "wasmbus://MBHGYVWJ24OQFNXTBSBMH4HSZWZ7DSRE3YW4QGG5QCQKRTBSBY2WQ4HY/" + i.Operation,
			OriginURL: "wasmbus://wasmcloud/httpserver/default/VBAG4WSBM6Y75EFWXV2BAGBP5NGEC36EAL4UOQEJAK5FKZ22UTP63FJV",
		},
	}

	var priKey ed25519.PrivateKey
	priKey = rKey

	var b bytes.Buffer
	b.WriteString(claims.Wascap.OriginURL)
	b.WriteString(claims.Wascap.TargetURL)
	b.WriteString(i.Operation)
	b.WriteString(string(i.Msg))
	hash := sha256.Sum256(b.Bytes())
	claims.Wascap.Hash = strings.ToUpper(hex.EncodeToString(hash[:]))

	token := jwt.NewWithClaims(&Ed25519SigningMethod, claims)
	token.Header["alg"] = "Ed25519"
	token.Header["typ"] = "jwt"

	jwtstring, err := token.SignedString(priKey)
	if err != nil {
		return err
	}

	if err != nil {
		return err
	}
	i.EncodedClaims = jwtstring

	return nil
}

type Claims struct {
	jwt.StandardClaims
	ID     string `json:"jti"`
	Wascap Wascap `json:"wascap"`
}

type InvocationResponse struct {
	InvocationID string `msgpack:"invocation_id"`
	Msg          []byte `msgpack:"msg,omitempty"`
	Error        string `msgpack:"error,omitempty"`
	InstanceID   string `msgpack:"instance_id,omitempty"`
}

type ProviderResponse struct {
	Msg   []byte `msgpack:"msg,omitempty"`
	Error string `msgpack:"error,omitempty"`
}

type Wascap struct {
	TargetURL string `json:"target_url"`
	OriginURL string `json:"origin_url"`
	Hash      string `json:"hash"`
}

type HostData struct {
	HostID             string            `json:"host_id"`
	LatticeRPCPrefix   string            `json:"lattice_rpc_prefix"`
	LinkName           string            `json:"link_name"`
	LatticeRPCUserJWT  string            `json:"lattice_rpc_user_jwt"`
	LatticeRPCUserSeed string            `json:"lattice_rpc_user_seed"`
	LatticeRPCURL      string            `json:"lattice_rpc_url"`
	ProviderKey        string            `json:"provider_key"`
	EnvValues          map[string]string `json:"env_values"`
	InvocationSeed     string            `json:"invocation_seed"`
	InstanceID         string            `json:"instance_id"`
	LinkDefinitions    []LinkDefinition  `json:"link_definitions"`
}

type Topics struct {
	LATTICE_LINKDEF_GET string
	LATTICE_LINKDEF_DEL string
	LATTICE_LINKDEF_PUT string
	LATTICE_SHUTDOWN    string
	LATTICE_HEALTH      string
}

func (h HostData) LatticeTopics() Topics {
	return Topics{
		LATTICE_LINKDEF_GET: fmt.Sprintf("wasmbus.rpc.%s.%s.%s.linkdefs.get", h.LatticeRPCPrefix, h.ProviderKey, h.LinkName),
		LATTICE_LINKDEF_DEL: fmt.Sprintf("wasmbus.rpc.%s.%s.%s.linkdefs.del", h.LatticeRPCPrefix, h.ProviderKey, h.LinkName),
		LATTICE_LINKDEF_PUT: fmt.Sprintf("wasmbus.rpc.%s.%s.%s.linkdefs.put", h.LatticeRPCPrefix, h.ProviderKey, h.LinkName),
		LATTICE_SHUTDOWN:    fmt.Sprintf("wasmbus.rpc.%s.%s.%s.shutdown", h.LatticeRPCPrefix, h.ProviderKey, h.LinkName),
		LATTICE_HEALTH:      fmt.Sprintf("wasmbus.rpc.%s.%s.%s.health", h.LatticeRPCPrefix, h.ProviderKey, h.LinkName),
	}
}

type HealthCheck struct {
	Placeholder bool `msgpack:"placeholder"`
}

type WasmcloudProvider struct {
	cancel            context.CancelFunc
	Links             chan ActorConfig
	Shutdown          chan struct{}
	NatsConnection    *nats.Conn
	HostData          HostData
	TopicData         Topics
	NatsSubscriptions []*nats.Subscription
	ProviderAction    chan ProviderAction
}

type ProviderAction struct {
	Operation string
	Msg       []byte
	Respond   chan ProviderResponse
}

func Init(ctx context.Context) (WasmcloudProvider, error) {
	_, cancel := context.WithCancel(ctx)
	p := WasmcloudProvider{cancel: cancel}

	reader := bufio.NewReader(os.Stdin)
	hostDataRaw, err := reader.ReadString('\n')
	if err != nil {
		return WasmcloudProvider{}, err
	}

	hostDataDecoded, err := base64.StdEncoding.DecodeString(hostDataRaw)
	if err != nil {
		return WasmcloudProvider{}, err
	}

	hostData := HostData{}
	err = json.Unmarshal([]byte(hostDataDecoded), &hostData)
	if err != nil {
		return WasmcloudProvider{}, err
	}

	nc, err := nats.Connect(hostData.LatticeRPCURL)
	if err != nil {
		return WasmcloudProvider{}, err
	}

	p.NatsConnection = nc
	p.HostData = hostData
	p.TopicData = hostData.LatticeTopics()
	p.Links = make(chan ActorConfig)
	p.Shutdown = make(chan struct{})

	p.subToNats()
	return p, nil
}

func (p *WasmcloudProvider) subToNats() {
	subs := []*nats.Subscription{}
	p.NatsSubscriptions = subs

	p.NatsConnection.QueueSubscribe(
		p.HostData.LatticeTopics().LATTICE_LINKDEF_GET,
		p.HostData.LatticeTopics().LATTICE_LINKDEF_GET,
		func(m *nats.Msg) {
			msg, err := msgpack.Marshal(p.HostData.LinkDefinitions)
			if err != nil {
				log.Printf("Failed to pack msgpack: %s\n", err)
			}
			p.NatsConnection.Publish(m.Reply, msg)
		})

	// Respond with an empty struct to satisfy health check
	p.NatsConnection.Subscribe(p.HostData.LatticeTopics().LATTICE_HEALTH,
		func(m *nats.Msg) {
			msg, err := msgpack.Marshal(struct{}{})
			if err != nil {
				log.Printf("Failed to pack msgpack: %s\n", err)
			}
			p.NatsConnection.Publish(m.Reply, msg)
		})

	p.NatsConnection.Subscribe(p.HostData.LatticeTopics().LATTICE_LINKDEF_DEL,
		func(m *nats.Msg) {
			var linkdef LinkDefinition
			err := msgpack.Unmarshal(m.Data, &linkdef)
			if err != nil {
				log.Printf("Failed to unpack msgpack: %s\n", err)
				return
			}

			// Trigger the cancel context for the server
			if p.cancel != nil {
				p.cancel()
			} else {
				log.Printf("Provider not running for actor: %s\n", linkdef.ActorID)
			}
		})

	p.NatsConnection.Subscribe(p.HostData.LatticeTopics().LATTICE_LINKDEF_PUT,
		func(m *nats.Msg) {
			var linkdef LinkDefinition
			err := msgpack.Unmarshal(m.Data, &linkdef)
			if err != nil {
				log.Error(err)
				return
			}
			p.Links <- ActorConfig{linkdef.ActorID, linkdef.Values}
		})

	p.NatsConnection.Subscribe(p.HostData.LatticeTopics().LATTICE_SHUTDOWN,
		func(m *nats.Msg) {
			p.Shutdown <- struct{}{}
			log.Print("Shutdown signal sent to provider")
		})
}

func (p *WasmcloudProvider) ListenForActor(actorID string) {
	subj := fmt.Sprintf("wasmbus.rpc.default.%s.default",
		p.HostData.ProviderKey,
	)
	p.ProviderAction = make(chan ProviderAction)

	p.NatsConnection.Subscribe(subj,
		func(m *nats.Msg) {
			i := Invocation{}
			_ = msgpack.Unmarshal(m.Data, &i)

			payload := ProviderAction{
				Operation: i.Operation,
				Msg:       i.Msg,
				Respond:   make(chan ProviderResponse, 1),
			}

			p.ProviderAction <- payload

			log.Print("Waiting for providers response")

			resp := <-payload.Respond
			ir := InvocationResponse{
				Msg:          resp.Msg,
				Error:        resp.Error,
				InstanceID:   i.HostID,
				InvocationID: i.ID,
			}

			rawIr, err := msgpack.Marshal(ir)
			if err != nil {
				log.Error(err)
				ir := InvocationResponse{Error: err.Error()}
				rawIr, _ := msgpack.Marshal(ir)
				p.NatsConnection.Publish(m.Reply, rawIr)
				return
			}

			log.WithField("invocation_response", ir).
				WithField("raw", rawIr).
				Print(string(rawIr))

			p.NatsConnection.Publish(m.Reply, rawIr)
		})
}
