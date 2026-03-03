package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type DefaultDNSBehaviorMode string

const (
	DefaultDNSModeForward DefaultDNSBehaviorMode = "forward"
	DefaultDNSModeDrop    DefaultDNSBehaviorMode = "drop"
)

type DefaultDNSBehavior struct {
	Mode           DefaultDNSBehaviorMode `yaml:"mode"`
	ForwardResolver string                `yaml:"forward_resolver"`
}

type GlobalConfig struct {
	ListenAddress      string              `yaml:"listen_address"`
	DefaultDNSBehavior DefaultDNSBehavior  `yaml:"default_dns_behavior"`
}

type BackendConfig struct {
	ID      string `yaml:"id"`
	Address string `yaml:"address"`
}

type PoolConfig struct {
	Name         string          `yaml:"name"`
	DomainSuffix string          `yaml:"domain_suffix"`
	Backends     []BackendConfig `yaml:"backends"`
}

type DnsttProtocolConfig struct {
	Pools []PoolConfig `yaml:"pools"`
}

type ProtocolsConfig struct {
	Dnstt DnsttProtocolConfig `yaml:"dnstt"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

type Config struct {
	Global    GlobalConfig    `yaml:"global"`
	Protocols ProtocolsConfig `yaml:"protocols"`
	Logging   LoggingConfig   `yaml:"logging"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

