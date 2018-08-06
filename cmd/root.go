// Copyright © 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"
	"runtime/trace"

	"github.com/clearlinux/diva/internal/config"
	"github.com/clearlinux/diva/internal/helpers"

	"github.com/spf13/cobra"
)

const version = "0.0.0"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "diva",
	Short: "DIstribution Validation Appliance",
	Long: `diva provides validation on Clearlinux content. Including:
RPM content, bundle information, full buildroot, manifests, fullfiles, packs,
and more.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// fmt.Printf("trace is %#v\n", rootCmdFlags)
		if rootCmdFlags.trace {
			f, err := os.Create("trace.out")
			if err != nil {
				panic(err)
			}

			err = trace.Start(f)
			if err != nil {
				panic(err)
			}
			rootCmdFlags.cleanup = func() { trace.Stop(); _ = f.Close() }
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if rootCmdFlags.cleanup != nil {
			rootCmdFlags.cleanup()
		}
		cmd.Print("trace complete, use 'go tool trace -trace=trace.out' to visulize\n")
	},
	Run: func(cmd *cobra.Command, args []string) {
		if rootCmdFlags.version {
			fmt.Printf("diva %s\n", version)
			os.Exit(0)
		}
	},
}

var rootCmdFlags = struct {
	version    bool
	configPath string
	trace      bool   // Enable go runtime tracing
	cleanup    func() // cleanup function run at the end  of -trace
}{}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.Flags().BoolVar(&rootCmdFlags.version,
		"version", false, "Print version information and exit")
	rootCmd.PersistentFlags().StringVarP(&rootCmdFlags.configPath,
		"config", "c", "", "optional path to configuration file")
	rootCmd.PersistentFlags().BoolVar(&rootCmdFlags.trace,
		"trace", false, "trace to trace.out")
}

var conf *config.Config

func initConfig() {
	var err error
	conf, err = config.ReadConfig(rootCmdFlags.configPath)
	helpers.FailIfErr(err)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Command finished\n")
}
