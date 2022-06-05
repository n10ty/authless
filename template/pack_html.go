//go:build pack_templates
// +build pack_templates

package main

import (
	"flag"
	"io/ioutil"
	log "github.com/sirupsen/logrus"
	"strings"
	"os"
	"github.com/stoewer/go-strcase"
)

func main() {
	var path *string
	path = flag.String("path", "./template", "Path to folder with templates")
	output = flag.String("output", "template.go", "Output file with packed templates")
	flag.Parse()

	files, err := ioutil.ReadDir(*path)
	if err != nil {
		log.Error(err)
	}

	templateFile, err := os.OpenFile(*path+"/"+"template.go", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0777)
	if err != nil {
		log.Error(err)
	}
	templateFile.WriteString("//go:build pack_templates\n")
	templateFile.WriteString("// +build pack_templates\n\n")
	templateFile.WriteString("package template\n\n")
	for _, file := range files {
		name := file.Name()
		if strings.HasSuffix(name, ".html") {
			fullPath := *path + "/" + file.Name()
			varName := strcase.LowerCamelCase(strings.ReplaceAll(name, ".html", ""))
			f, err := ioutil.ReadFile(fullPath)
			if err != nil {
				log.Error(err)
			}
			content := string(f)
			content = strings.ReplaceAll(content, "\n", "")
			content = strings.ReplaceAll(content, "  ", "")
			templateFile.WriteString("var " + varName + "=`")
			templateFile.WriteString(content)
			templateFile.WriteString("`\n\n")
			log.Infof("Packing %s", fullPath)
		}
	}
}
