package kafka

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	LOG "github.com/vinllen/log4go"
	"github.com/xdg-go/scram"

	"github.com/Shopify/sarama"
	utils "github.com/alibaba/MongoShake/v2/common"
	"github.com/rcrowley/go-metrics"
)

var (
	topicDefault           = "mongoshake"
	topicSplitter          = "@"
	brokersSplitter        = ","
	defaultPartition int32 = 0
)

type Option func(*Config)

func WithSASL(user, passwd string) Option {
	return func(c *Config) {
		c.Config.Net.SASL.Enable = true
		c.Config.Net.SASL.User = user
		c.Config.Net.SASL.Password = passwd
		c.Config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
		c.Config.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return &XDGSCRAMClient{HashGeneratorFcn: SHA256}
		}

	}
}

type Message struct {
	Key       []byte
	Value     []byte
	Offset    int64
	TimeStamp time.Time
}

type Config struct {
	Config *sarama.Config
}

func NewConfig(rootCaFile string, opts ...Option) (*Config, error) {
	config := sarama.NewConfig()
	config.Version = sarama.V0_10_0_0
	config.MetricRegistry = metrics.NewRegistry()

	config.Producer.Return.Errors = true
	config.Producer.Return.Successes = true
	config.Producer.Partitioner = sarama.NewManualPartitioner
	config.Producer.MaxMessageBytes = 16*utils.MB + 2*utils.MB // 2MB for the reserve gap

	// ssl
	if rootCaFile != "" {
		sslConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		caCert, err := ioutil.ReadFile(rootCaFile)
		if err != nil {
			LOG.Critical("failed to load the ca cert file[%s]: %s failed: %s", rootCaFile, err.Error())
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		sslConfig.RootCAs = caCertPool
		config.Net.TLS.Config = sslConfig
		config.Net.TLS.Enable = true
	}

	retConfig := &Config{
		Config: config,
	}

	for _, f := range opts {
		f(retConfig)
	}

	return retConfig, nil
}

// parse the address (topic@broker1,broker2,...)
func parse(address string) (string, []string, error) {
	arr := strings.Split(address, topicSplitter)
	l := len(arr)
	if l == 0 || l > 2 {
		return "", nil, fmt.Errorf("address format error")
	}

	topic := topicDefault
	if l == 2 {
		topic = arr[0]
	}

	brokers := strings.Split(arr[l-1], brokersSplitter)
	return topic, brokers, nil
}

// ----------------------------------------------------------------------------
var (
	SHA256 scram.HashGeneratorFcn = sha256.New
	SHA512 scram.HashGeneratorFcn = sha512.New
)

type XDGSCRAMClient struct {
	*scram.Client
	*scram.ClientConversation
	scram.HashGeneratorFcn
}

func (x *XDGSCRAMClient) Begin(userName, password, authzID string) (err error) {
	x.Client, err = x.HashGeneratorFcn.NewClient(userName, password, authzID)
	if err != nil {
		return err
	}
	x.ClientConversation = x.Client.NewConversation()
	return nil
}

func (x *XDGSCRAMClient) Step(challenge string) (response string, err error) {
	response, err = x.ClientConversation.Step(challenge)
	return
}

func (x *XDGSCRAMClient) Done() bool {
	return x.ClientConversation.Done()
}
