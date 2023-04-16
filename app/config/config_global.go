package config

const MAX_COUNT = 20

type GlobalConfig struct {
    Quiet       bool
    AfterRead   bool
    Name        string
    GetLR       bool
    GetPC       bool
    Debug       bool
    Uid         uint64
    Pid         uint64
    SysCall     string
    NoSysCall   string
    NoTid       string
    LogFile     string
    Is32Bit     bool
    NoUidFilter bool
    Bypass      bool
    ExecPath    string
}

func NewGlobalConfig() *GlobalConfig {
    config := &GlobalConfig{}
    return config
}

func (this *GlobalConfig) GetFilter(systable_config SysTableConfig) (Filter, error) {
    filter := Filter{}
    if this.NoUidFilter {
        // 强制忽略uid过滤
        filter.SetUid(0)
    } else {
        filter.SetUid(uint32(this.Uid))
    }
    filter.SetPid(uint32(this.Pid))
    filter.SetArch(this.Is32Bit)
    filter.SetByPass(this.Bypass)
    filter.SetAfterRead(this.AfterRead)
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
