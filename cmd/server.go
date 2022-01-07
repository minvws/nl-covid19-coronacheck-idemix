package cmd

import (
	"fmt"
	"github.com/minvws/nl-covid19-coronacheck-idemix/issuer/localsigner"
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

	flags.String("public-key-usages", "dynamic,static", "Public key usages, when no keys map has been provided through configuration")
	flags.String("public-key-id", "TST-KEY-01", "Public key identifier, when no keys map has been provided through configuration")
	flags.String("public-key-path", "pk.xml", "Path to public key, when no keys map has been provided through configuration")
	flags.String("private-key-path", "sk.xml", "Path to private key, when no keys map has been provided through configuration")

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

	usageKeys := map[string]*localsigner.Key{}

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

		err = viper.UnmarshalKey("usage-keys", &usageKeys)
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not unmarshal usage keys configuration", 0)
		}
	}

	// If no usages keys were provided, add the default that is provided as command line option
	if len(usageKeys) == 0 {
		usages := viper.GetString("public-key-usages")
		for _, usage := range strings.Split(usages, ",") {
			usageKeys[usage] = &localsigner.Key{
				PkId: viper.GetString("public-key-id"),
				PkPath: viper.GetString("public-key-path"),
				SkPath: viper.GetString("private-key-path"),
			}
		}
	}

	config := &server.Configuration{
		ListenAddress: viper.GetString("listen-address"),
		ListenPort:    viper.GetString("listen-port"),

		UsageKeys: usageKeys,

		PrimePoolSize:        viper.GetUint64("prime-pool-size"),
		PrimePoolLwm:         viper.GetUint64("prime-pool-lwm"),
		PrimePoolHwm:         viper.GetUint64("prime-pool-hwm"),
		PrimePoolPrimeStart:  viper.GetUint("prime-pool-prime-start"),
		PrimePoolPrimeLength: viper.GetUint("prime-pool-prime-length"),
		PrimePoolMaxCores:    viper.GetInt("prime-pool-max-cores"),
	}

	return config, nil
}
