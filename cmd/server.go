package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"github.com/minvws/nl-covid19-coronacheck-idemix/issuer/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

	flags.String("static-public-key-id", "TST-KEY-01", "Public key identifier for static issuance")
	flags.String("static-public-key-path", "pk.xml", "Path to public key for static issuance")
	flags.String("static-private-key-path", "sk.xml", "Path to private key for static issuance")

	flags.Uint("prime-pool-size", 0, "Number of primes to buffer")
	flags.Uint("prime-pool-lwm", 100, "Low water mark when the buffer is considered depleted")
	flags.Uint("prime-pool-hwm", 1000, "High water mark when the buffer is considered not depleted")
	flags.Int("prime-pool-max-cores", -1, "Number of cores to use for generation. use -1 for all cores")
	flags.Uint("prime-pool-prime-start", common.GabiSystemParameters.Le-1, "Start bits of the primes")
	flags.Uint("prime-pool-prime-length", common.GabiSystemParameters.LePrime-1, "Length range of the primes")
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

		StaticPublicKeyId:    viper.GetString("static-public-key-id"),
		StaticPublicKeyPath:  viper.GetString("static-public-key-path"),
		StaticPrivateKeyPath: viper.GetString("static-private-key-path"),

		PrimePoolSize:        viper.GetUint64("prime-pool-size"),
		PrimePoolLwm:         viper.GetUint64("prime-pool-lwm"),
		PrimePoolHwm:         viper.GetUint64("prime-pool-hwm"),
		PrimePoolPrimeStart:  viper.GetUint("prime-pool-prime-start"),
		PrimePoolPrimeLength: viper.GetUint("prime-pool-prime-length"),
		PrimePoolMaxCores:    viper.GetInt("prime-pool-max-cores"),
	}

	return config, nil
}
