// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package testfalco

import (
	"regexp"
	"strings"
	"testing"

	"github.com/falcosecurity/testing/pkg/falco"
	"github.com/falcosecurity/testing/tests"
	"github.com/falcosecurity/testing/tests/data/outputs"
	"github.com/falcosecurity/testing/tests/data/rules"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// todo(jasondellaluce): implement tests for the non-covered Falco cmds/args:
// Commands printing information:
//   -h, --help, --support, -l, --list, --list-syscall-events,
//   --markdown, -N, --gvisor-generate-config, --page-size
// Metadata collection and container runtimes:
//   --cri, --disable-cri-async, -k, --k8s-api, -K, --k8s-api-cert, --k8s-node, -m, --mesos-api
// Falco event collection modes:
//   -g, --gvisor-config, --gvisor-root, -u, --userspace, --modern-bpf
// Changers of Falco's behavior:
//   --disable-source, --enable-source, -A, -d, --daemon, -P, --pidfile,
//   -p, --print, -b, --print-base64, -S, --snaplen,
// Misc Falco features:
//   -s, --stats-interval, -U, --unbuffered

const (
	semVerRegex     string = `((0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)`
	commitHashRegex string = `([a-f0-9]+)`
	tagRegex        string = `[0-9]+\.[0-9]+\.[0-9]`
)

func TestFalco_Cmd_Version(t *testing.T) {
	t.Parallel()
	checkDefaultConfig(t)
	runner := tests.NewFalcoExecutableRunner(t)
	t.Run("text-output", func(t *testing.T) {
		t.Parallel()
		res := falco.Test(runner, falco.WithArgs("--version"))
		assert.NoError(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 0)
		// Falco version supports:
		// - (dev) -> 0.36.0-198+30aa28f
		// - (release) -> 0.36.0
		// - (release-rc) -> 0.36.0-rc1
		// Libs version supports:
		// - (commit hash) -> e999e61fa8f57ca8e9590e4c108fd4a12459ec48
		// - (release) -> 0.13.0
		// - (release-rc) -> 0.13.0-rc1
		// Default driver supports:
		// - (commit hash) -> e999e61fa8f57ca8e9590e4c108fd4a12459ec48
		// - (release) -> 6.0.1+driver
		// - (release-rc) -> 6.0.1-rc1+driver
		assert.Regexp(t, regexp.MustCompile(
			`Falco version:[\s]+`+semVerRegex+`[\s]+`+
				`Libs version:[\s]+(`+semVerRegex+`|`+commitHashRegex+`)[\s]+`+
				`Plugin API:[\s]+`+tagRegex+`[\s]+`+
				`Engine:[\s]+`+tagRegex+`[\s]+`+
				`Driver:[\s]+`+
				`API version:[\s]+`+tagRegex+`[\s]+`+
				`Schema version:[\s]+`+tagRegex+`[\s]+`+
				`Default driver:[\s]+(`+semVerRegex+`|`+commitHashRegex+`)[\s]*`),
			res.Stdout())
	})
	t.Run("json-output", func(t *testing.T) {
		t.Parallel()
		res := falco.Test(runner,
			falco.WithArgs("--version"),
			falco.WithOutputJSON(),
		)
		out := res.StdoutJSON()
		assert.NoError(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 0)
		assert.Contains(t, out, "default_driver_version")
		assert.Contains(t, out, "driver_api_version")
		assert.Contains(t, out, "driver_schema_version")
		assert.Contains(t, out, "engine_version")
		assert.Contains(t, out, "falco_version")
		assert.Contains(t, out, "libs_version")
		assert.Contains(t, out, "plugin_api_version")
	})
}

func TestFalco_Cmd_ListPlugins(t *testing.T) {
	t.Parallel()
	checkDefaultConfig(t)
	checkNotStaticExecutable(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithArgs("--list-plugins"),
		falco.WithArgs("-o", "load_plugins[0]=cloudtrail"),
		falco.WithArgs("-o", "load_plugins[1]=json"),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, res.ExitCode(), 0)
	assert.Regexp(t, regexp.MustCompile(
		`2 Plugins Loaded:[\s]+`+
			`Name: cloudtrail[\s]+`+
			`Description: .*[\s]+`+
			`Contact: .*[\s]+`+
			`Version: .*[\s]+`+
			`Capabilities:[\s]+`+
			`- Event Sourcing \(ID=2, source='aws_cloudtrail'\)[\s]+`+
			`- Field Extraction[\s]+`+
			`Name: json[\s]+`+
			`Description: .*[\s]+`+
			`Contact: .*[\s]+`+
			`Version: .*[\s]+`+
			`Capabilities:[\s]+`+
			`[\s]+`+
			`- Field Extraction`),
		res.Stdout())
}

func TestFalco_Cmd_PluginInfo(t *testing.T) {
	t.Parallel()
	checkDefaultConfig(t)
	checkNotStaticExecutable(t)
	res := falco.Test(
		tests.NewFalcoExecutableRunner(t),
		falco.WithArgs("--plugin-info=cloudtrail"),
		falco.WithArgs("-o", "load_plugins[0]=cloudtrail"),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, res.ExitCode(), 0)
	assert.Regexp(t, regexp.MustCompile(
		`Name: cloudtrail[\s]+`+
			`Description: .*[\s]+`+
			`Contact: .*[\s]+`+
			`Version: .*[\s]+`+
			`Capabilities:[\s]+`+
			`- Event Sourcing \(ID=2, source='aws_cloudtrail'\)[\s]+`+
			`- Field Extraction[\s]+`+
			`Init config schema type: JSON[\s]+.*[\s]+`+
			`No suggested open params available.*`),
		res.Stdout())
}

func TestFalco_Print_IgnoredEvents(t *testing.T) {
	t.Parallel()
	checkDefaultConfig(t)
	bytearr, err := outputs.EventData.Content()
	if err != nil {
		panic(err)
	}
	events := strings.Split(string(bytearr), ",")
	runner := tests.NewFalcoExecutableRunner(t)
	res := falco.Test(
		runner,
		falco.WithArgs("-i"),
	)
	assert.Contains(t, res.Stdout(), "Ignored syscall(s)")
	for _, event := range events {
		assert.Contains(t, res.Stdout(), event)
	}
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, res.ExitCode(), 0)
}

func TestFalco_Print_Rules(t *testing.T) {
	t.Parallel()
	checkDefaultConfig(t)
	runner := tests.NewFalcoExecutableRunner(t)

	t.Run("invalid-rules", func(t *testing.T) {
		t.Parallel()
		res := falco.Test(
			runner,
			falco.WithArgs("-L"),
			falco.WithRules(rules.InvalidRuleOutput),
		)
		assert.Error(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 1)
	})

	t.Run("text-valid-rules", func(t *testing.T) {
		t.Parallel()
		res := falco.Test(
			runner,
			falco.WithArgs("-L"),
			falco.WithRules(rules.DetectConnectUsingIn, rules.ListAppend, rules.CatchallOrder),
		)
		rules := []string{"Open From Cat", "Localhost connect", "open_dev_null", "dev_null"}
		for _, rule := range rules {
			assert.Contains(t, res.Stdout(), rule)
		}
		assert.NoError(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 0)
	})

	t.Run("json-valid-rules", func(t *testing.T) {
		t.Parallel()
		res := falco.Test(
			runner,
			falco.WithArgs("-L"),
			falco.WithOutputJSON(),
			falco.WithArgs("-o", "load_plugins[0]=json"),
			falco.WithRules(rules.RulesDir000SingleRule, rules.RulesListWithPluginJSON),
		)

		infos := res.RulesetDescription()
		assert.NotNil(t, infos)

		// check required engine version
		assert.Equal(t, "0.11.0", infos.RequiredEngineVersion)

		// check required plugin versions
		require.Len(t, infos.RequiredPluginVersions, 1)
		assert.Equal(t, "json", infos.RequiredPluginVersions[0].Name)
		assert.Equal(t, "0.1.0", infos.RequiredPluginVersions[0].Version)

		// check list elements
		require.Len(t, infos.Lists, 2)

		assert.Equal(t, "cat_binaries", infos.Lists[0].Info.Name)
		require.Len(t, infos.Lists[0].Info.Items, 1)
		assert.Equal(t, "cat", infos.Lists[0].Info.Items[0])
		assert.True(t, infos.Lists[0].Details.Used)
		assert.Len(t, infos.Lists[0].Details.Lists, 0)
		assert.Len(t, infos.Lists[0].Details.Plugins, 0)
		assert.Len(t, infos.Lists[0].Details.ItemsCompiled, 1)
		assert.Equal(t, "cat", infos.Lists[0].Info.Items[0])

		assert.Equal(t, "cat_capable_binaries", infos.Lists[1].Info.Name)
		assert.Len(t, infos.Lists[1].Info.Items, 0)
		assert.True(t, infos.Lists[1].Details.Used)
		require.Len(t, infos.Lists[1].Details.Lists, 1)
		assert.Equal(t, "cat_binaries", infos.Lists[1].Details.Lists[0])
		assert.Len(t, infos.Lists[1].Details.Plugins, 0)
		require.Len(t, infos.Lists[1].Details.ItemsCompiled, 1)
		assert.Equal(t, "cat", infos.Lists[1].Details.ItemsCompiled[0])

		// check macro elements
		require.Len(t, infos.Macros, 1)

		assert.Equal(t, "is_cat", infos.Macros[0].Info.Name)
		assert.Equal(t, "proc.name in (cat_capable_binaries)", infos.Macros[0].Info.Condition)
		assert.True(t, infos.Macros[0].Details.Used)
		assert.Len(t, infos.Macros[0].Details.Macros, 0)
		assert.Len(t, infos.Macros[0].Details.Lists, 1)
		assert.Equal(t, "cat_capable_binaries", infos.Macros[0].Details.Lists[0])
		assert.Len(t, infos.Macros[0].Details.Plugins, 0)
		assert.NotEmpty(t, infos.Macros[0].Details.Events)
		assert.Len(t, infos.Macros[0].Details.ConditionOperators, 1)
		assert.Equal(t, "in", infos.Macros[0].Details.ConditionOperators[0])
		require.Len(t, infos.Macros[0].Details.ConditionFields, 1)
		assert.Equal(t, "proc.name", infos.Macros[0].Details.ConditionFields[0])
		assert.Equal(t, "proc.name in (cat)", infos.Macros[0].Details.ConditionCompiled)

		// check rule elements
		require.Len(t, infos.Rules, 1)

		assert.Equal(t, "open_from_cat", infos.Rules[0].Info.Name)
		assert.Equal(t, `evt.type=open and is_cat and json.value[/test] = "test"`, infos.Rules[0].Info.Condition)
		assert.Equal(t, "A process named cat does an open", infos.Rules[0].Info.Description)
		assert.Equal(t, "An open was seen (command=%proc.cmdline)", infos.Rules[0].Info.Output)
		assert.Equal(t, true, infos.Rules[0].Info.Enabled)
		assert.Equal(t, "Warning", infos.Rules[0].Info.Priority)
		assert.Equal(t, "syscall", infos.Rules[0].Info.Source)
		assert.Empty(t, infos.Rules[0].Info.Tags)
		require.Len(t, infos.Rules[0].Details.Plugins, 1)
		assert.Equal(t, "json", infos.Rules[0].Details.Plugins[0])
		require.Len(t, infos.Rules[0].Details.OutputFields, 1)
		assert.Equal(t, "proc.cmdline", infos.Rules[0].Details.OutputFields[0])
		assert.Equal(t, infos.Rules[0].Info.Output, infos.Rules[0].Details.OutputCompiled)
		assert.Len(t, infos.Rules[0].Details.Macros, 1)
		require.Equal(t, "is_cat", infos.Rules[0].Details.Macros[0])
		assert.Len(t, infos.Rules[0].Details.Lists, 0)
		assert.Len(t, infos.Rules[0].Details.ExceptionFields, 0)
		assert.Len(t, infos.Rules[0].Details.ExceptionOperators, 0)
		assert.Len(t, infos.Rules[0].Details.ExceptionNames, 0)
		assert.Len(t, infos.Rules[0].Details.Events, 2)
		assert.Contains(t, infos.Rules[0].Details.Events, "open")
		assert.Contains(t, infos.Rules[0].Details.Events, "asyncevent")
		assert.Len(t, infos.Rules[0].Details.ConditionOperators, 2)
		assert.Contains(t, infos.Rules[0].Details.ConditionOperators, "=")
		assert.Contains(t, infos.Rules[0].Details.ConditionOperators, "in")
		assert.Len(t, infos.Rules[0].Details.ConditionFields, 3)
		assert.Contains(t, infos.Rules[0].Details.ConditionFields, "evt.type")
		assert.Contains(t, infos.Rules[0].Details.ConditionFields, "proc.name")
		assert.Contains(t, infos.Rules[0].Details.ConditionFields, "json.value[/test]")
		assert.Equal(t, `(evt.type = open and proc.name in (cat) and json.value[/test] = test)`, infos.Rules[0].Details.ConditionCompiled)
	})
}

func TestFlaco_Rule_Info(t *testing.T) {
	t.Parallel()
	runner := tests.NewFalcoExecutableRunner(t)
	t.Run("valid-rule-name", func(t *testing.T) {
		res := falco.Test(
			runner,
			falco.WithRules(rules.DisabledRuleUsingEnabledFlagOnly),
			falco.WithArgs("-l"),
			falco.WithArgs("open_from_cat"),
		)
		assert.NoError(t, res.Err(), "%s", res.Stderr())
		assert.Regexp(t,
			`.*Rule[\s]+Description[\s]+`+
				`[\-]+[\s]+[\-]+[\s]+`+
				`open_from_cat[\s]+A process named cat does an open`,
			res.Stdout())
	})
	t.Run("invalid-rule-name", func(t *testing.T) {
		res := falco.Test(
			runner,
			falco.WithRules(rules.DisabledRuleUsingEnabledFlagOnly),
			falco.WithArgs("-l"),
			falco.WithArgs("invalid"),
		)
		assert.NoError(t, res.Err(), "%s", res.Stderr())
		assert.Regexp(t,
			`.*Rule[\s]+Description[\s]+`+
				`[\-]+[\s]+[\-]+[\s]+`,
			res.Stdout())
	})
}


func TestFalco_Cmd_Help(t *testing.T) {
	t.Parallel()
	checkDefaultConfig(t)
	runner := tests.NewFalcoExecutableRunner(t)
	t.Run("text-output", func(t *testing.T) {
		t.Parallel()
		res := falco.Test(runner, falco.WithArgs("--help"))
		assert.NoError(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 0)
		
		assert.Regexp(t, regexp.MustCompile(
			`Falco - Cloud Native Runtime Security` +
			`Usage:`+
			`\s{2}falco [OPTION...]`+
			``+
			
			`\s{2}-h, --help\s+ Print this help list and exit.`+
			
			`\s{2}-c <path>\s+ Configuration file. If not specified uses /etc/falco/falco.yaml`+
			
			`\s{2}-A\s+ Monitor all events supported by Falco and defined in rules and configs. Some events are ignored by default\n 
			\s+ when -A is not specified (the -i option lists these events ignored). Using -A can impact performance. This\n 
			\s+ option has no effect when reproducing events from a capture file.`+
			
			`\s{2}-b, --print-base64\s+ Print data buffers in base64. This is useful for encoding binary data that needs to be used over media\n
			\s+ designed to consume this format.` + 
			
			`\s{6}--cri <path>\s+ Path to CRI socket for container metadata. Use the specified <path> to fetch data from a CRI-compatible\n 
			\s+ runtime. If not specified, built-in defaults for commonly known paths are used. This option can be passed\n 
			\s+ multiple times to specify a list of sockets to be tried until a successful one is found.`+

			`\s{6}--disable-cri-async\s+ Turn off asynchronous CRI metadata fetching. This is useful to let the input event wait for the container\n
			\s+ metadata fetch to finish before moving forward. Async fetching, in some environments leads to empty fields\n
			\s+ for container metadata when the fetch is not fast enough to be completed asynchronously. This can have a\n
			\s+ performance penalty on your environment depending on the number of containers and the frequency at which\n
			\s+ they are created/started/stopped.`+

			`\s{6}--disable-source <event_source>\n 
			\s+ Turn off a specific <event_source>. By default, all loaded sources get enabled. Available sources are\n
			\s+ 'syscall' plus all sources defined by loaded plugins supporting the event sourcing capability. This option\n
			\s+ can be passed multiple times, but turning off all event sources simultaneously is not permitted. This \n
			\s+ option can not be mixed with --enable-source. This option has no effect when reproducing events from a\n
			\s+ capture file.`+

			`\s{6}--dry-run\s+ Run Falco without processing events. It can help check that the configuration and rules do not have any\n 
			\s+ errors.` +
			
			`\s{2}-D <substring>\s+ Turn off any rules with names having the substring <substring>. This option can be passed multiple times.\n 
			\s+ It cannot be mixed with -t.` + 
			
			`\s{2}-e <events_file>\s+ Reproduce the events by reading from the given <capture_file> instead of opening a live session. Only\n
			\s+ capture files in .scap format are supported.`+
	
			`\s{6}--enable-source <event_source>\n
			\s+ Enable a specific <event_source>. By default, all loaded sources get enabled. Available sources are\n
			\s+ 'syscall' plus all sources defined by loaded plugins supporting the event sourcing capability. This option\n 
			\s+ can be passed multiple times. When using this option, only the event sources specified by it will be\n 
			\s+ enabled. This option can not be mixed with --disable-source. This option has no effect when reproducing\n 
			\s+ events from a capture file.` +

			`\s{2}-g, --gvisor-config <gvisor_config>\n
			\s+ Collect 'syscall' events from gVisor using the specified <gvisor_config> file. A Falco-compatible 
			\s+ configuration file can be generated with --gvisor-generate-config and utilized for both runsc and Falco.` + 
			
			`\s{6}--gvisor-generate-config [=<socket_path>(=/run/falco/gvisor.sock)]\n
			\s+ Generate a configuration file that can be used for gVisor and exit. See --gvisor-config for more details.` +
			
			`\s{6}--gvisor-root <gvisor_root>\n
			\s+ Set gVisor root directory for storage of container state when used in conjunction with --gvisor-config. The\n
			\s+ <gvisor_root> to be passed is the one usually passed to runsc --root flag.` +
			
			`\s{6}--modern-bpf\s+ Use the BPF modern probe driver to instrument the kernel and observe 'syscall' events.`+
			
			`\s{2}-i\s+ Print those events that are ignored by default for performance reasons and exit. See -A for more details.`+

			`\s{2}-k, --k8s-api <URL>\s+ Enable Kubernetes metadata support by connecting to the given API server <URL>\n
			\s+ (e.g. "http://admin:password@127.0.0.1:8080". The API server can also be specified via the environment\n
			\s+ variable FALCO_K8S_API.`+

			`\s{2}-K, --k8s-api-cert (<bt_file> | <cert_file>:<key_file[#password]>[:<ca_cert_file>])\n
			\s+ Use the provided file names to authenticate the user and (optionally) verify the K8S API server identity.\n
			\s+ Each entry must specify the full (absolute or relative to the current directory) path to the respective\n
			\s+ file. Passing a private key password is optional (unless the key is password-protected). CA certificate is\n
			\s+ optional. For all files, only the PEM file format is supported. Specifying the CA certificate only is\n
			\s+ obsoleted - when a single entry is provided for this option, it will be interpreted as the name of a file\n
			\s+ containing the bearer token. Note that the format of this command-line option prohibits the use of files\n
			\s+ whose names contain ':' or '#' characters in the file name. This option has effect only when used in\n
			\s+ conjunction with -k.`+
			
			`\s{6}--k8s-node <node_name>\s+ Filter Kubernetes metadata for a specified <node_name>. The node name will be used as a filter when\n 
			\s+ requesting metadata of pods to the API server. Usually, this should be set to the current node on which\n
			\s+ Falco is running. No filter is set if empty, which may have a performance penalty on large clusters. This\n
			\s+ option has effect only when used in conjunction with -k.`+
			
			
			`\s{2}-L\s+ Show the name and description of all rules and exit. If json_output is set to true, it prints details about\n
				all rules, macros, and lists in JSON format.`+
			
			`\s{2}-l <rule>\s+ Show the name and description of the rule specified <rule> and exit. If json_output is set to true, it\n
			\s+ prints details about the rule in JSON format.`+
			
			`\s{6}--list [=<source>(=)] List all defined fields and exit. If <source> is provided, only list those fields for the source <source>.\n
			\s+ Current values for <source> are "syscall" or any source from a configured plugin with event sourcing\n
			\s+ capability.`+
			
			`\s{6}--list-events\s+ List all defined syscall events, metaevents, tracepoint events and exit.`+
			
			`\s{6}--list-plugins\s+ Print info on all loaded plugins and exit.`+
			
			`\s{2}-M\s+ <num_seconds>\s+ Stop Falco execution after <num_seconds> are passed. (default: 0)`+
			
			`\s{6}--markdown\s Print output in Markdown format when used in conjunction with --list or --list-events options. It has no\n 
			\s+ effect when used with other options.`+
			
			`\s{2}-N\s+ Only print field names when used in conjunction with the --list option. It has no effect when used with\n
			\s+ other options.`+
			
			`\s{6}--nodriver\s+ Do not use a driver to instrument the kernel. If a loaded plugin has event-sourcing capability and can\n
			\s+ produce system events, it will be used for event collection. Otherwise, no event will be collected.`+
			
			`\s{2}-o, --option <opt>=<val>\s+ Set the value of option <opt> to <val>. Overrides values in the configuration file. <opt> can be identified\n
			\s+ using its location in the configuration file using dot notation. Elements of list entries can be accessed\n
			\s+ via square brackets [].\n
			\s+E.g. base.id = val\n
			\s+ base.subvalue.subvalue2 = val\n 
			\s+ base.list[1]=val`+
			
			`\s{6}--plugin-info <plugin_name>\n 
			\s+ Print info for the plugin specified by <plugin_name> and exit.\n
			\s+ This includes all descriptive information like name and author, along with the\n
			\s+ schema format for the init configuration and a list of suggested open parameters.\n
			\s+ <plugin_name> can be the plugin's name or its configured 'library_path'.`+
			
			`\s{2}-p, --print <output_format>\s+ Print (or replace) additional information in the rule's output.\n
			\s+ Use -pc or -pcontainer to append container details.\n
			\s+ Use -pk or -pkubernetes to add both container and Kubernetes details.\n
			\s+ If using gVisor, choose -pcg or -pkg variants (or -pcontainer-gvisor and -pkubernetes-gvisor, respectively).\n
			\s+ If a rule's output contains %%container.info, it will be replaced with the corresponding details. Otherwise,\n
			\s+ these details will be directly appended to the rule's output.\n
			\s+ Alternatively, use -p <output_format> for a custom format. In this case, the given <output_format> will be\n
			\s+ appended to the rule's output without any replacement.`+
			
			`\s{2}-P, --pidfile <pid_file>\s+ Write PID to specified <pid_file> path. By default, no PID file is created. (default: "")`+
			
			`\s{2}-r <rules_file> Rules file or directory to be loaded. This option can be passed multiple times. Falco defaults to the\n
			\s+ values in the configuration file when this option is not specified.`+
			
			`\s{2}-S, --snaplen <len>\s+ Collect only the first <len> bytes of each I/O buffer for 'syscall' events. By default, the first 80 bytes\n
			\s+ are collected by the driver and sent to the user space for processing. Use this option with caution since\n
			\s+ it can have a strong performance impact. (default: 0)`+

			`\s{6}--support\s+ Print support information, including version, rules files used, loaded configuration, etc., and exit. The\n
			\s+ output is in JSON format.`+
			
			`\s{2}-T <tag>\s+ Turn off any rules with a tag=<tag>. This option can be passed multiple times. This option can not be mixed\n
			\s+ with -t.`+
			
			`\s{2}-t <tag>\s+ Only enable those rules with a tag=<tag>. This option can be passed multiple times. This option can not be\n
			\s+ mixed with -T/-D.`+
			
			`\s{2}-U, --unbuffered\s+ Turn off output buffering for configured outputs. This causes every single line emitted by Falco to be\n
			\s+ flushed, which generates higher CPU usage but is useful when piping those outputs into another process or a\n
			\s script.`+
			
			`\s{2}-u, --userspace [DEPRECATED: this option will be removed in Falco 0.37] Use a userspace driver to collect 'syscall' events.\n
			\s+ To be used in conjunction with the ptrace(2) based driver (pdig).`+
			
			`\s{2}-V, --validate <rules_file>\s+ Read the contents of the specified <rules_file> file(s), validate the loaded rules, and exit. This option\n
			\s+ can be passed multiple times to validate multiple files.`+
		
			`\s{2}-v\s+ Enable verbose output.`+
			
			`\s{6}--version\s+ Print version information and exit.`+
			
			`\s{6}--page-size\s+ Print the system page size and exit. This utility may help choose the right syscall ring buffer size.`+),
		 res.Stdout())
	})
}
