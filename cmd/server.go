package cmd

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-idemix/issuer/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"path/filepath"
	"strings"
)

var serverCmd = &cobra.Command{
	Use: "server",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := configureServer(cmd)
		if err != nil {
			exitWithError(err)
		}

		err = server.Run(config)
		if err != nil {
			exitWithError(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	setServerFlags(serverCmd)
}

func setServerFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.SortFlags = false

	flags.String("config", "", "path to configuration file (JSON, TOML, YAML or INI)")
	flags.String("listen-address", "localhost", "address at which to listen")
	flags.String("listen-port", "4001", "port at which to listen")

	flags.String("public-key-id", "TST-KEY-01", "Public key identifier")
	flags.String("public-key-path", "pk.xml", "Path to public key")
	flags.String("private-key-path", "sk.xml", "Path to private key")
}

func configureServer(cmd *cobra.Command) (*server.Configuration, error) {
	err := viper.BindPFlags(cmd.Flags())
	if err != nil {
		return nil, err
	}

	configPath := viper.GetString("config")
	if configPath != "" {
		dir, file := filepath.Dir(configPath), filepath.Base(configPath)
		viper.SetConfigName(strings.TrimSuffix(file, filepath.Ext(file)))
		viper.AddConfigPath(dir)

		err = viper.ReadInConfig()
		if err != nil {
			msg := fmt.Sprintf("Could not read or apply config file %s", configPath)
			return nil, errors.WrapPrefix(err, msg, 0)
		}
	}

	config := &server.Configuration{
		ListenAddress: viper.GetString("listen-address"),
		ListenPort:    viper.GetString("listen-port"),

		PublicKeyId:    viper.GetString("public-key-id"),
		PublicKeyPath:  viper.GetString("public-key-path"),
		PrivateKeyPath: viper.GetString("private-key-path"),
	}

	return config, nil
}
