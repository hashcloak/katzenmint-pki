package main

import (
	//"errors"

	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	katzenmint "github.com/hashcloak/katzenmint-pki"
	kcfg "github.com/hashcloak/katzenmint-pki/config"
	"github.com/spf13/viper"
	abci "github.com/tendermint/tendermint/abci/types"
	cfg "github.com/tendermint/tendermint/config"
	tmflags "github.com/tendermint/tendermint/libs/cli/flags"
	"github.com/tendermint/tendermint/libs/log"
	nm "github.com/tendermint/tendermint/node"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/proxy"
	"github.com/tendermint/tendermint/rpc/client/http"
	dbm "github.com/tendermint/tm-db"
)

var (
	configFile string
)

func readConfig(configFile string) (config *cfg.Config, err error) {
	config = cfg.DefaultConfig()
	config.RootDir = filepath.Dir(filepath.Dir(configFile))
	viper.SetConfigFile(configFile)
	if err = viper.ReadInConfig(); err != nil {
		err = fmt.Errorf("viper failed to read config file: %w", err)
		return
	}
	if err = viper.Unmarshal(config); err != nil {
		err = fmt.Errorf("viper failed to unmarshal config: %w", err)
		return
	}
	if err = config.ValidateBasic(); err != nil {
		err = fmt.Errorf("config is invalid: %w", err)
		return
	}
	return
}

func joinNetwork(config *cfg.Config) error {
	// prepare AddAuthority transaction
	pv := privval.LoadFilePV(
		config.PrivValidatorKeyFile(),
		config.PrivValidatorStateFile(),
	)
	tx, err := katzenmint.EncodeJson(katzenmint.Authority{
		Auth:    config.Moniker,
		Power:   1,
		PubKey:  pv.Key.PubKey.Bytes(),
		KeyType: pv.Key.PubKey.Type(),
	})
	if err != nil {
		return err
	}

	// connect to peers and post transaction
	peers := append(
		strings.Split(config.P2P.PersistentPeers, ","),
		strings.Split(config.P2P.Seeds, ",")...,
	)
	for _, element := range peers {
		addr := strings.Trim(element, " ")
		rpc, err := http.New(addr, "/websocket")
		if err != nil {
			continue
		}
		resp, err := rpc.BroadcastTxSync(context.Background(), tx)
		if err == nil && resp.Code == abci.CodeTypeOK {
			return nil
		}
	}
	return fmt.Errorf("cannot connect and broadcast to peers")
}

func newTendermint(app abci.Application, config *cfg.Config, logger log.Logger) (node *nm.Node, err error) {

	// read private validator
	pv := privval.LoadFilePV(
		config.PrivValidatorKeyFile(),
		config.PrivValidatorStateFile(),
	)

	// read node key
	var nodeKey *p2p.NodeKey
	if nodeKey, err = p2p.LoadNodeKey(config.NodeKeyFile()); err != nil {
		return nil, fmt.Errorf("failed to load node's key: %w", err)
	}

	// create node
	node, err = nm.NewNode(
		config,
		pv,
		nodeKey,
		proxy.NewLocalClientCreator(app),
		nm.DefaultGenesisDocProviderFunc(config),
		nm.DefaultDBProvider,
		nm.DefaultMetricsProvider(config.Instrumentation),
		logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create new Tendermint node: %w", err)
	}

	return node, nil
}

func init() {
	flag.StringVar(&configFile, "config", "katzenmint.toml", "Path to katzenmint.toml")
	flag.Parse()
}

func main() {
	kConfig, err := kcfg.LoadFile(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}
	config, err := readConfig(kConfig.TendermintConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}
	db, err := dbm.NewDB("katzenmint_db", dbm.BadgerDBBackend, kConfig.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open badger db: %v\ntry running with -tags badgerdb\n", err)
		os.Exit(1)
	}
	defer db.Close()

	logger := log.NewTMLogger(log.NewSyncWriter(os.Stdout))
	if logger, err = tmflags.ParseLogLevel(config.LogLevel, logger, cfg.DefaultLogLevel); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse log level: %v", err)
		os.Exit(1)
	}

	app := katzenmint.NewKatzenmintApplication(kConfig, db, logger)
	node, err := newTendermint(app, config, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(2)
	}

	if !kConfig.Membership {
		err = joinNetwork(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v", err)
			os.Exit(2)
		}
		kConfig.Membership = true
		err = kcfg.SaveFile(configFile, kConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error saving config: %v", err)
		}
	}

	if err = node.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(2)
	}
	defer func() {
		_ = node.Stop()
		node.Wait()
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	os.Exit(0)
}
