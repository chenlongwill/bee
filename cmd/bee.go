// Copyright 2013 bee authors
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Package cmd ...
package cmd

import (
	"bee/cmd/commands"
	_ "bee/cmd/commands/api"
	_ "bee/cmd/commands/bale"
	_ "bee/cmd/commands/beefix"
	_ "bee/cmd/commands/dlv"
	_ "bee/cmd/commands/dockerize"
	_ "bee/cmd/commands/generate"
	_ "bee/cmd/commands/hprose"
	_ "bee/cmd/commands/migrate"
	_ "bee/cmd/commands/new"
	_ "bee/cmd/commands/pack"
	_ "bee/cmd/commands/rs"
	_ "bee/cmd/commands/run"
	_ "bee/cmd/commands/server"
	_ "bee/cmd/commands/version"
	"bee/utils"
)

func IfGenerateDocs(name string, args []string) bool {
	if name != "generate" {
		return false
	}
	for _, a := range args {
		if a == "docs" {
			return true
		}
	}
	return false
}

var usageTemplate = `Bee is a Fast and Flexible tool for managing your Beego Web Application.

{{"USAGE" | headline}}
    {{"bee command [arguments]" | bold}}

{{"AVAILABLE COMMANDS" | headline}}
{{range .}}{{if .Runnable}}
    {{.Name | printf "%-11s" | bold}} {{.Short}}{{end}}{{end}}

Use {{"bee help [command]" | bold}} for more information about a command.

{{"ADDITIONAL HELP TOPICS" | headline}}
{{range .}}{{if not .Runnable}}
    {{.Name | printf "%-11s"}} {{.Short}}{{end}}{{end}}

Use {{"bee help [topic]" | bold}} for more information about that topic.
`

var helpTemplate = `{{"USAGE" | headline}}
  {{.UsageLine | printf "bee %s" | bold}}
{{if .Options}}{{endline}}{{"OPTIONS" | headline}}{{range $k,$v := .Options}}
  {{$k | printf "-%s" | bold}}
      {{$v}}
  {{end}}{{end}}
{{"DESCRIPTION" | headline}}
  {{tmpltostr .Long . | trim}}
`

var ErrorTemplate = `bee: %s.
Use {{"bee help" | bold}} for more information.
`

func Usage() {
	utils.Tmpl(usageTemplate, commands.AvailableCommands)
}

func Help(args []string) {
	if len(args) == 0 {
		Usage()
	}
	if len(args) != 1 {
		utils.PrintErrorAndExit("Too many arguments", ErrorTemplate)
	}

	arg := args[0]

	for _, cmd := range commands.AvailableCommands {
		if cmd.Name() == arg {
			utils.Tmpl(helpTemplate, cmd)
			return
		}
	}
	utils.PrintErrorAndExit("Unknown help topic", ErrorTemplate)
}
