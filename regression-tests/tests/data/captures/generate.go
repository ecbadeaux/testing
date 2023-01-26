//go:build ignore
// +build ignore

package main

import (
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/iancoleman/strcase"
)

type headerInfo struct {
	Timestamp time.Time
	Package   string
}

type fileInfo struct {
	VarName  string
	FileName string
	FilePath string
}

var headerTemplate = template.Must(template.New("header").Parse(`// Code generated by go generate; DO NOT EDIT.
// This file was generated by robots at {{ .Timestamp }}

package {{ .Package }}

import (
	"github.com/falcosecurity/falco/regression-tests/pkg/utils"
)
`))

var fileTemplate = template.Must(template.New("file").Parse(`
var {{ .VarName }} = utils.NewLocalFileAccessor("{{ .FileName }}", "{{ .FilePath }}")
`))

func die(err error) {
	if err != nil {
		log.Fatal(err.Error())
	}
}

func genDirectoryRules(w io.Writer, dirPath, namePath string) {
	files, err := ioutil.ReadDir(dirPath)
	die(err)
	for _, file := range files {
		fname := dirPath + file.Name()
		vname := namePath + file.Name()

		if file.IsDir() {
			// todo: re-enable recursive dir exploration
			// genDirectoryRules(w, fname+"/", dirPath+fname+"_")
			continue
		}

		ext := path.Ext(file.Name())
		if ext != ".scap" {
			continue
		}

		absPath, err := filepath.Abs(fname)
		die(err)
		fileTemplate.Execute(w, fileInfo{
			VarName:  strcase.ToCamel(strings.TrimSuffix(path.Base(vname), ext)),
			FileName: path.Base(file.Name()),
			FilePath: absPath,
		})
	}
}

func main() {
	out, err := os.Create("captures_gen.go")
	die(err)
	defer out.Close()

	headerTemplate.Execute(out, headerInfo{
		Timestamp: time.Now(),
		Package:   "captures",
	})

	genDirectoryRules(out, "./files/", "")
}