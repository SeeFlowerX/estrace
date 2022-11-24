package config

type GlobalConfig struct {
    Quiet    bool
    Name     string
    GetLR    bool
    Debug    bool
    Uid      uint64
    Pid      uint64
    NR       uint64
    SysCall  string
    LogFile  string
    Is32Bit  bool
    ExecPath string
}

type Filter struct {
    uid uint32
    pid uint32
    nr  uint32
}

func (this *Filter) GetNR() uint32 {
    return this.nr
}

func (this *Filter) UpdateNR(nr uint32) {
    this.nr = nr
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
        is_32bit: this.Is32Bit,
    }
    return arch
}
