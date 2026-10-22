// Package perf mede o desempenho de uma execução (duração por etapa, CPU e pico de memória da unidade) e limita o
// ritmo pela pressão do servidor (PSI), conforme o escopo, seções 12 e 12.1. A leitura de /proc e do cgroup fica
// atrás de fs.FS e funções injetáveis para os testes rodarem fora do Linux.
package perf

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"strconv"
	"strings"
)

// PressureStat é a pressão "some" de um recurso: porcentagem do tempo em que ao menos uma tarefa esperou por ele,
// nas janelas de 10 s, 60 s e 300 s.
type PressureStat struct {
	Avg10  float64 `json:"avg10"`
	Avg60  float64 `json:"avg60"`
	Avg300 float64 `json:"avg300"`
}

// Pressure é a pressão de CPU, E/S e memória do servidor inteiro.
type Pressure struct {
	Available bool         `json:"available"`
	CPU       PressureStat `json:"cpu"`
	IO        PressureStat `json:"io"`
	Memory    PressureStat `json:"memory"`
}

// ParsePressure interpreta um arquivo de /proc/pressure e devolve a linha "some".
func ParsePressure(data []byte) (PressureStat, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || fields[0] != "some" {
			continue
		}
		var st PressureStat
		found := 0
		for _, f := range fields[1:] {
			k, v, ok := strings.Cut(f, "=")
			if !ok {
				continue
			}
			n, err := strconv.ParseFloat(v, 64)
			if err != nil || n < 0 {
				return PressureStat{}, errors.New("valor de pressão inválido: " + f)
			}
			switch k {
			case "avg10":
				st.Avg10, found = n, found+1
			case "avg60":
				st.Avg60, found = n, found+1
			case "avg300":
				st.Avg300, found = n, found+1
			}
		}
		if found < 3 {
			return PressureStat{}, errors.New("linha some incompleta")
		}
		return st, nil
	}
	return PressureStat{}, errors.New("linha some ausente")
}

// ReadPressure lê proc/pressure/{cpu,io,memory} a partir da raiz (em produção, os.DirFS("/")). Available só fica
// verdadeiro com os três arquivos legíveis.
func ReadPressure(root fs.FS) Pressure {
	var p Pressure
	ok := 0
	for _, r := range []struct {
		name string
		dst  *PressureStat
	}{{"cpu", &p.CPU}, {"io", &p.IO}, {"memory", &p.Memory}} {
		data, err := fs.ReadFile(root, "proc/pressure/"+r.name)
		if err != nil {
			continue
		}
		if st, err := ParsePressure(data); err == nil {
			*r.dst = st
			ok++
		}
	}
	p.Available = ok == 3
	return p
}

// ParseLoadAvg devolve a carga média de 15 minutos de /proc/loadavg.
func ParseLoadAvg(data []byte) (float64, error) {
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, errors.New("loadavg incompleto")
	}
	return strconv.ParseFloat(fields[2], 64)
}
