package config

type TableConfig struct {
	Count uint32
	Name  string
	Mask  uint32
}

type SysTableConfig map[string]TableConfig

func NewSysTableConfig() SysTableConfig {
	config := make(SysTableConfig)
	return config
}

func loadConfig() {
	// 从assets中直接加载 解析为结构体
}
