package config

type SymbolConfig struct {
	Symbol  string
	Library string
	Offset  uint64
}

func (this *SymbolConfig) GetSoInfoFilter() (SoInfoFilter, error) {
	filter := SoInfoFilter{}
	return filter, nil
}
