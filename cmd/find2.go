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
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/clearlinux/diva/pkginfo"
	"github.com/spf13/cobra"
)

type find2CmdFlags struct {
	repoURL  string
	repoName string
	version  string
	update   bool
}

// flags passed in as args
var find2Flags find2CmdFlags

func init() {
	checkCmd.AddCommand(find2Cmd)
	find2Cmd.Flags().StringVarP(&find2Flags.repoURL, "repourl", "u", "", "Url to repo")
	find2Cmd.Flags().StringVarP(&find2Flags.repoName, "reponame", "n", "clear", "Name of repo")
	find2Cmd.Flags().StringVarP(&find2Flags.version, "version", "v", "0", "Version to check")
	find2Cmd.Flags().BoolVar(&find2Flags.update, "update", false, "Update repo RPMs")
}

// find2Cmd is a reimplimentation of find2.py
// It needs a repo as a parameter to check
var find2Cmd = &cobra.Command{
	Use:   "find2",
	Short: "check for missing requires",
	Long:  "check for missing requires",
	Run: func(cmd *cobra.Command, args []string) {
		doFind2(os.Stdout, args)
	},
}

func doFind2(w io.Writer, args []string) {
	repo := pkginfo.Repo{
		URI:     find2Flags.repoURL,
		Name:    find2Flags.repoName,
		Version: find2Flags.version,
		Type:    "B",
	}

	err := checkAll(&repo)
	fmt.Fprintf(w, "Nothing to see here (%v)\n", err)
}

// Go doesn't have constant arrays.
var evilPaths = []string{"/etc/", "/var/"}

// ErrMissingDependency is an error type
var ErrMissingDependency = errors.New("Missing dependency")

// checkRequires looks at all the rpms in the passed in repo, and checks that for every requirement listed, at least
// one rpm provides it
func checkRequires(repo *pkginfo.Repo) (err error) {
	requires := make(map[string][]*pkginfo.RPM) // Map of all requirments to the rpms that need them
	provides := make(map[string]bool)
	fileSet := make(map[string]bool)
	for _, rpm := range repo.Packages { // foreach rpm
		for _, i := range rpm.Requires { // record that this rpm has this requirement
			requires[i] = append(requires[i], rpm)
		}
		for _, i := range rpm.Provides {
			provides[i] = true // this rpm (at least) provides things
		}
		// record all the filenames, in case someone is using a filename as a requirement
		for _, file := range rpm.Files {
			fileSet[file.Name] = true
		}
	}

	missing := make(map[string]bool) // This map is not needed, could just print out the missing things immediatly
	for i := range requires {        // foreach potential requirement from any rpm
		if val, ok := provides[i]; ok && val {
			continue // Something provided it
		}
		if val, ok := fileSet[i]; ok && val {
			continue // It looks like a filename and something has that filename
		}
		missing[i] = true
	}
	for x := range missing {
		fmt.Printf("Missing dependency %s is required by:\n", x)
		for _, i := range requires[x] {
			fmt.Printf("\t%s\n", i.Name)
		}
		fmt.Printf("\n")
		err = ErrMissingDependency
	}
	return err
}

func checkAll(repo *pkginfo.Repo) error {
	var err error
	if err = pkginfo.PopulateRepo(repo, ""); err != nil {
		return err
	}
	err = checkRequires(repo)
	if err != nil {
		return err
	}
	fmt.Printf("All OK\n")
	return err
}

var badPaths = make(map[string]bool) // set of paths

// # whitelisted "bad path" packages
// whitelist = ["filesystem-"]

// # get at least one line of output.
// def get_output(cmd):
//     try:
//         o = subprocess.check_output(shlex.split(cmd)).decode('utf-8')
//         if "\n" not in o:
//             print("Failed command: %s " % cmd)
//             sys.exit(1)
//         return o
//     except Exception as e:
//         print("Error: %s" % e)
//         sys.exit(1)

// def addBathPath(pkg, path):
//     global badPaths
//     global evilPaths
//     global whitelist

//     # create whitelist of pkgs
//     wlist = [x for x in whitelist if pkg.startswith(x)]
//     if len(wlist) > 0:
//         return
//     matches = [x for x in evilPaths if path.startswith(x)]
//     if len(matches) == 0:
//         return

//     if pkg not in badPaths:
//         badPaths[pkg] = set()
//     badPaths[pkg].add(path)

//
// def get_bundle_contents(base, version):
//     srcrpms = set()

//     os_packages_f = os.path.join(base, "image", version, "os-packages")
//     try:
//         with open(os_packages_f, "r") as opf:
//             for line in opf.readlines():
//                 _, srcrpm = line.split("\t")
//                 srcrpm = srcrpm.strip()
//                 srcrpms.add(srcrpm)
//     except:
//         print("Error when reading {}".format(os_packages_f))
//         srcrpms = set()

//     return srcrpms

// getAllPackages should parse the file
// e.g. https://download.clearlinux.org/releases/24250/clear/source/package-sources
// whose typical line looks like 3 tab separated fields. everything is small so
// acme	0.26.1	36
// (name, version, release)
// and return a map of string to string.
func getAllPackages(base string, version string, mash_id string) (map[string]string, error) {
	r = make(map[string]string)
	sources := base
	if mash_id == "" {
		sources = filepath.Join(sources, "releases", version)
	}
	sources = filepath.Join(sources, "clear", "source", "package-sources")
	file, err := os.Open(sources)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Close(file) }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields = string.Split(scanner.Text(), "\t")
		if len(fields) != 3 {
			return nil, error.New("Error building full packages list from " + sources)
		}
		r[fmt.Sprintf("%s-%s-%s", fields[0], fields[1], fields[2])] = fields[0]
	}

	return r, nil
}

// def get_all_packages(base, version, mash_id=None):
//     sources = base
//     if not mash_id:
//         sources =  os.path.join(sources, "releases", version)
//     sources = os.path.join(sources, "clear/source/package-sources")

//     packages = dict()

//     try:
//         with open(sources, "r") as file:
//             lines = file.readlines()
//         for line in lines:
//             name, ver, rel = line.split("\t")
//             srcrpm = "{}-{}-{}.src.rpm".format(name.strip(), ver.strip(),
//                                                rel.strip())
//             packages[srcrpm] = name
//     except:
//         print("Error building full packages list from {}".format(sources))
//         packages = dict()

//     return packages

// def resolve_orphan_dependencies(bundled, orphans, package_files, provides,
//                                 required, to_check):
//     new_check = {}
//     new_required = False

//     for srcrpm, package in to_check.items():
//         used = False
//         for dep in provides.get(srcrpm, ()):
//             if used:
//                 break
//             for req in required.get(dep, ()):
//                 if req in bundled:
//                     used = True
//                     break
//         for file in package_files.get(srcrpm, ()):
//             if used:
//                 break
//             for req in required.get(file, ()):
//                 if req in bundled:
//                     used = True
//                     break
//         if used:
//             bundled.add(srcrpm)
//             new_required = True
//         else:
//             new_check[srcrpm] = package

//     if new_required:
//         return resolve_orphan_dependencies(bundled, orphans, package_files,
//                                            provides, required, new_check)
//     else:
//         return new_check

// def get_orphaned_packages(base, package_files, provides, required, version):
//     bundled = get_bundle_contents(base, version)
//     packages = get_all_packages(base, version)

//     to_check = {x: packages[x] for x in packages if x not in bundled}
//     orphans = resolve_orphan_dependencies(bundled, dict(), package_files,
//                                           provides, required, to_check)

//     return orphans

// def checkAll(base, statusMode, version, mash_id=None):
//     global badPaths

//     base_dir = base
//     if not mash_id:
//         base_dir = os.path.join(base, "releases", version)
//     bin_dir = os.path.join(base_dir, "clear/x86_64/os/Packages")
//     src_dir = os.path.join(base_dir, "clear/source/SRPMS")

//     # query the database, using .= as a field splitter
//     # stuff in [ ] is iterated over in parallel. The {} is filled in by the .format()., {{ and }} get changed to { and }
//     # So from this we get some output
//     ```
// SourceRPM.=libdwarf-20150115-8.src.rpm
// ff7828f5492219ef9a7e8fa61a951cf7        /usr/include/libdwarf/common.h  -rw-r--r--
// 18d4dda07a6ea8823c888e3b98f56a83        /usr/include/libdwarf/config.h  -rw-r--r--
// a26efe003417bca362fe5a4833326e2b        /usr/include/libdwarf/dwarf.h   -rw-r--r--
// .....
// 6242a210d9364fec2fe541a63317a7ed        /usr/include/libdwarf/pro_types.h       -rw-r--r--
// d0ef6d45fd0aa7382cfd2375de39472e        /usr/include/libdwarf/pro_util.h        -rw-r--r--
// cf0b2c057cf9b201d7801c6d530d9df0        /usr/lib64/libdwarf.so  -rwxr-xr-x
// PROVIDES.=libdwarf-dev
// PROVIDES.=libdwarf-dev(x86-64)
// PROVIDES.=libdwarf-devel
// PROVIDES.=libdwarf.so()(64bit)
// REQUIRES.=libc.so.6()(64bit)
// REQUIRES.=libc.so.6(GLIBC_2.14)(64bit)
// REQUIRES.=libc.so.6(GLIBC_2.2.5)(64bit)
// REQUIRES.=libc.so.6(GLIBC_2.3.4)(64bit)
// REQUIRES.=libc.so.6(GLIBC_2.4)(64bit)
// REQUIRES.=rpmlib(CompressedFileNames)
// REQUIRES.=rpmlib(PayloadFilesHavePrefix)
// REQUIRES.=rpmlib(PayloadIsXz)
// ```

/*
 The following 2 commands query the rpm database, once for source and once for bin.

The output is a series of lines. Using {{...}} for variable parts it looks like

SourceRPM.={{.SOURCERPM}}
{{with .FILENAMES}}
{{.MD5HASH}}	{{.FILENAMES}}	{{.FILEMODES}}
{{end}}
{{with .PROVIDES}}
PROVIDES.={{.}}
{{end}}
{{with .REQUIRES}}
REQUIRES.={{.}}
{{end}}

and it runs it for each rpm in $bin_dir/*.rpm
*/

//     bin_cmd = 'rpm --queryformat="SourceRPM.=%{{SOURCERPM}}\n[%{{FILEMD5S}}\t%{{FILENAMES}}\t%{{FILEMODES:perms}}\n][PROVIDES.=%{{PROVIDES}}\n][REQUIRES.=%{{REQUIRES}}\n]" -qp {}/*.rpm'.format(bin_dir)
//     src_cmd = 'rpm --queryformat="SourceRPM.=%{{RPMTAG_NAME}}-%{{RPMTAG_VERSION}}-%{{RPMTAG_RELEASE}}.src.rpm\n[REQUIRES.=%{{REQUIRES}}\n]" -qp {}/*.rpm'.format(src_dir)

//     currentSrc = None

//     required = dict()
//     provides = dict()
//     rev_provides = dict()
//     packageFiles = dict()
//     rev_packageFiles = dict()
//     fileSet = set()
//     badPaths = dict()

//     # magic internal requires
//     internal = [
//         "rpmlib(CompressedFileNames)",
//         "rpmlib(PayloadFilesHavePrefix)",
//         "rpmlib(PayloadIsXz)",
//         "rpmlib(ScriptletInterpreterArgs)",
//         "rpmlib(PartialHardlinkSets)",
//     ]

//     for i in internal:
//         provides[i] = "__rpm_internal__"

//     builder = io.StringIO()
//     orphaned_builder = io.StringIO()
//     whitelist_builder = io.StringIO()

// # loop over output lines
// # /SourceRPM/ { currentSrc=s/SourceRPM.=// ; next}
// # /PROVIDES/ { provides[$2] .= currentSrc ; next}
// # /REQUIRES/ { required[$2] .= currentSrc ; next}
// # otherwise if it is a directory skip it
// # otherwise if it is a symlink or regular file rev_packageFiles[currentSrc] .= $2

//     for line in get_output(bin_cmd).split("\n"):
//         orig_line = str(line)
//         line = line.strip()

//         # use the .= to see if this is a key line, e.g. PROVIDES, REQUIRES, SourceRPM
//         spl = line.split(".=")
//         if len(spl) > 1:
//             key = spl[0]
//             val = spl[1].split()[0]
//             if key == "SourceRPM":
//                 currentSrc = spl[1]
//             elif key == "REQUIRES":
//                 # handle REQUIRES
//                 if val not in required:
//                     required[val] = set()
//                 required[val].add(currentSrc)
//             elif key == "PROVIDES":
//                 # handle PROVIDES
//                 if val not in provides:
//                     provides[val] = set()
//                 if currentSrc not in rev_provides:
//                     rev_provides[currentSrc] = set()
//                 provides[val].add(currentSrc)
//                 rev_provides[currentSrc].add(val)
//             continue

//         # If not a SourceRPM, REQUIRES, or PROVIDES line, it is a tab-separated
//         # field listing metadata for a file, directory, or symlink.
//         filepath = None
//         directory = False
//         spl = line.split("\t")

//         if len(spl) == 2:
//             # no md5sum, so it's either a directory or symlink
//             filepath = spl[0]
//             fileperms = spl[1]
//             if fileperms[0] != 'l':
//                 directory = True
//         elif len(spl) == 3:
//             # this is a regular file
//             filepath = spl[1]
//         elif spl[0] == "":
//             # skip the single blank line at the end of the rpm output
//             continue
//         else:
//             # The line has the wrong number of fields. Skip for now.
//             continue

//         fileSet.add(filepath)
//         addBathPath(currentSrc, filepath)
//         # ignore directories for conflicts
//         if directory:
//             continue
//         if filepath not in packageFiles:
//             packageFiles[filepath] = set()
//         if currentSrc not in rev_packageFiles:
//             rev_packageFiles[currentSrc] = set()
//         packageFiles[filepath].add(currentSrc)
//         rev_packageFiles[currentSrc].add(filepath)

// # do simular loop over srcrpms, but just get REQUIRES
//     for line in get_output(src_cmd).split("\n"):
//         orig_line = str(line)
//         line = line.strip()

//         spl = line.split(".=")
//         if len(spl) > 1:
//             key = spl[0]
//             val = spl[1].split()[0]
//             if key == "SourceRPM":
//                 currentSrc = spl[1]
//             elif key == "REQUIRES":
//                 # handle REQUIRES
//                 if val not in required:
//                     required[val] = set()
//                 required[val].add(currentSrc)

//     # Create list of packages shipped in a Clear Linux bundle
//     if not mash_id:
//         for srcrpm in get_bundle_contents(base, version):
//             whitelist_builder.write(srcrpm)
//             whitelist_builder.write("\n")
//         whitelist = whitelist_builder.getvalue()
//         whitelist_builder.close()

//     # Firstly handle missing dependencies
//     missing = [x for x in required if x not in provides and x not in fileSet]

//     for x in missing:
//         what = required[x]
//         builder.write("Missing dependency %s is required by:\n%s" % (x, "\n".join(what)))
//         builder.write("\n")

//     # Find the conflicts and map them between the relevant packages
//     conflictMap = dict()
//     for fpath in packageFiles:
//         comp = packageFiles[fpath]
//         if len(comp) == 1:
//             continue
//         key = " and ".join(comp)

//         if key not in conflictMap:
//             conflictMap[key] = set()
//         conflictMap[key].add(fpath)

//     for conflict in conflictMap:
//         builder.write("Package file conflict between %s\n" % conflict)
//         for path in conflictMap[conflict]:
//             builder.write("  - > %s\n" % path)
//         builder.write("\n")

//     # Emit bad paths
//     for pkg in badPaths:
//         builder.write("Package containing blacklisted paths: %s\n" % pkg)
//         for path in badPaths[pkg]:
//             builder.write("  - > %s\n" % path)
//         builder.write("\n")

//     output = builder.getvalue()
//     builder.close()

//     # Emit orphaned packages

//     if not mash_id:
//         orphans = get_orphaned_packages(base, rev_packageFiles,
//                                         rev_provides, required, version)
//         for orphan in sorted(orphans.values()):
//             orphaned_builder.write(orphan)
//             orphaned_builder.write("\n")

//     orphaned = orphaned_builder.getvalue()
//     orphaned_builder.close()

//     # Normal CLI print
//     if not statusMode:
//         for line in output.split("\n"):
//             print(line.encode('utf-8').strip())
//     else:
//         for (status_type, dashboard_url, content) in [('repoconflicts',
//                                                        "http://clr-dashboard.ostc.intel.com:8080/dashboard/version/%s/repoconflicts" % version,
//                                                        output),
//                                                       ('shipped_packages',
//                                                        "http://clr-dashboard.ostc.intel.com:8080/dashboard/version/%s/shipped_packages" % version,
//                                                        whitelist),
//                                                       ('orphaned_packages',
//                                                        "http://clr-dashboard.ostc.intel.com:8080/dashboard/version/%s/orphaned_packages" % version,
//                                                        orphaned)]:
//             data = { 'type': status_type, 'content': content }
//             data_out = urllib.parse.urlencode(data).encode('UTF-8')
//             try:
//                 response = urllib.request.urlopen(dashboard_url, data=data_out).read().decode('UTF-8', 'ignore')
//                 print("Dashboard got: %s" % response)
//                 print("with data %s" % content)
//             except Exception as e:
//                 print("Error communicating with host: %s" % e)

//     if mash_id:
//         report_mash(mash_id, conflictMap, badPaths, missing, required)

//     if len(conflictMap) > 0 or len(missing) > 0 or len(badPaths) > 0:
//         sys.exit(1)
//     sys.exit(0)

// def report_mash(mash_id, conflictMap, missing, badPaths, required):
//     import mashdash

//     mash_test = "find_conflicts"

//     mashdash.post_test(mash_id, mash_test)

//     for x in missing:
//         disposition = "Missing dependency %s is required by: %s" % (x, "\n".join(required[x]))
//         mashdash.post_disposition(mash_id, mash_test, disposition, 0)

//     for conflict in conflictMap:
//         disposition = "Package file conflict between %s: %s" % (conflict, conflictMap[conflict])
//         mashdash.post_disposition(mash_id, mash_test, disposition, 0)

//     for pkg in badPaths:
//         disposition = "Package containing blacklisted paths: %s: %s" % (pkg, str(badPaths))
//         mashdash.post_disposition(mash_id, mash_test, disposition, 0)

// def handle_options():
//     """Setup option parsing
//     """
//     parser = argparse.ArgumentParser()
//     parser.add_argument("-s", "--status-mode", action="store_true",
//                         default=False,
//                         help="Send output to status page")
//     parser.add_argument("-p", "--path", action="store", default=".",
//                         help="Path to scan")
//     parser.add_argument("-m", "--mash", action="store",
//                         default=None, help="Skip release checks")
//     parser.add_argument("version", action="store", default="666",
//                         help="Version to check")
//     args = parser.parse_args()

//     return args

// def main():
//     args = handle_options()
//     checkAll(args.path, args.status_mode, args.version, mash_id=args.mash)

// if __name__ == "__main__":
//     main()
