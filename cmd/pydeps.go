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
	"errors"
	"os"
	"path/filepath"

	"github.com/clearlinux/diva/diva"
	"github.com/clearlinux/diva/internal/config"
	"github.com/clearlinux/diva/internal/helpers"

	"github.com/spf13/cobra"
)

func init() {
	checkCmd.AddCommand(pyDepsCmd)
	pyDepsCmd.Flags().StringVarP(&pipFlags.path, "path", "p", "", "path to full chroot")
	pyDepsCmd.Flags().StringVarP(&pipFlags.version, "version", "v", "", "version to check")
}

type pyDepsCmdFlags struct {
	version string
	path    string
}

var pipFlags pyDepsCmdFlags

var pyDepsCmd = &cobra.Command{
	Use:   "pydeps",
	Short: "Run pip check against full chroot",
	Long: `Run pip check against full chroot at <path> or constructed using
local configuration and <version>. Verifies installed packages have compatible
dependencies.`,
	Run: runCheckPyDeps,
}

func runCheckPyDeps(cmd *cobra.Command, args []string) {
	if pipFlags.version == "" && pipFlags.path == "" {
		helpers.FailIfErr(errors.New("must supply either --version or --path argument"))
	}

	p := pipFlags.path
	if p == "" {
		c, err := config.ReadConfig("")
		helpers.FailIfErr(err)
		p = filepath.Join(c.Mixer.MixWorkSpace, "update/image", pipFlags.version, "full")
	}

	results := CheckPyDeps(p)
	if results.Failed > 0 {
		os.Exit(1)
	}
}

// CheckPyDeps runs 'pip check' in a chroot at path
func CheckPyDeps(path string) *diva.Results {
	name := "Python dependencies"
	desc := "run pip check in full build root to check for missing python requirements"
	r := diva.NewSuite(name, desc)
	r.Header(0)
	err := helpers.RunCommandSilent("chroot", path, "pip", "check")
	r.Ok(err == nil, desc)
	if err != nil {
		r.Diagnostic(err.Error())
	}
	return r
}
