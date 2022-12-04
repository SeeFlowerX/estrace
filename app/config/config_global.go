package config

const MAX_COUNT = 10

type GlobalConfig struct {
    Quiet     bool
    Name      string
    GetLR     bool
    Debug     bool
    Uid       uint64
    Pid       uint64
    SysCall   string
    NoSysCall string
    NoTid     string
    LogFile   string
    Is32Bit   bool
    ExecPath  string
}

func NewGlobalConfig() *GlobalConfig {
    config := &GlobalConfig{}
    return config
}

func (this *GlobalConfig) GetFilter(systable_config SysTableConfig) (Filter, error) {
    filter := Filter{}
    filter.SetUid(uint32(this.Uid))
    filter.SetPid(uint32(this.Pid))
    var err error = nil
    if this.SysCall != "" {
        err = filter.SetSysCall(this.SysCall, systable_config)
        if err != nil {
            return filter, err
        }
    }
    if this.NoSysCall != "" {
        err = filter.SetSysCallBlacklist(this.NoSysCall, systable_config)
        if err != nil {
            return filter, err
        }
    }
    if this.NoTid != "" {
        err = filter.SetTidBlacklist(this.NoTid)
        if err != nil {
            return filter, err
        }
    }
    return filter, err
}
