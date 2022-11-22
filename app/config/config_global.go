package config

type GlobalConfig struct {
    Quiet    bool
    Name     string
    GetLR    bool
    Debug    bool
    Uid      uint64
    Pid      uint64
    NR       uint64
    LogFile  string
    ExecPath string
}

type Filter struct {
    uid uint32
    pid uint32
    nr  uint32
}
type Arch struct {
    is_32bit bool
}

func NewGlobalConfig() *GlobalConfig {
    config := &GlobalConfig{}
    return config
}

func (this *GlobalConfig) GetFilter() Filter {
    filter := Filter{
        uid: uint32(this.Uid),
        pid: uint32(this.Pid),
        nr:  uint32(this.NR),
    }
    return filter
}

func (this *GlobalConfig) GetArch() Arch {
    arch := Arch{
        is_32bit: false,
    }
    return arch
}
