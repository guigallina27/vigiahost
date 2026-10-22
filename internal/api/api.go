// Package api contém os tipos e a interface de servidor gerados de api/openapi.yaml.
// Não edite api.gen.go à mão: altere o contrato e rode make generate.
package api

//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../../api/openapi.yaml
