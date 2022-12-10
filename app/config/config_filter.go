package config

import (
    "fmt"
    "strconv"
    "strings"
)

type Filter struct {
    uid                    uint32
    pid                    uint32
    is_32bit               uint32
    try_bypass             uint32
    after_read             uint32
    tid_blacklist_mask     uint32
    tid_blacklist          [MAX_COUNT]uint32
    syscall_mask           uint32
    syscall                [MAX_COUNT]uint32
    syscall_blacklist_mask uint32
    syscall_blacklist      [MAX_COUNT]uint32
}

func (this *Filter) SetUid(uid uint32) {
    this.uid = uid
}

func (this *Filter) SetPid(pid uint32) {
    this.pid = pid
}

func (this *Filter) SetSysCall(syscall string, systable_config SysTableConfig) error {
    items := strings.Split(syscall, ",")
    if len(items) > MAX_COUNT {
        return fmt.Errorf("max syscall whitelist count is %d, provided count:%d", MAX_COUNT, len(items))
    }
    for i, v := range items {
        nr, err := systable_config.GetNR(v)
        if err != nil {
            return err
        }
        this.syscall[i] = uint32(nr)
        this.syscall_mask |= (1 << i)
    }
    return nil
}

func (this *Filter) SetSysCallBlacklist(syscall_blacklist string, systable_config SysTableConfig) error {
    items := strings.Split(syscall_blacklist, ",")
    if len(items) > MAX_COUNT {
        return fmt.Errorf("max syscall blacklist count is %d, provided count:%d", MAX_COUNT, len(items))
    }
    for i, v := range items {
        nr, err := systable_config.GetNR(v)
        if err != nil {
            return err
        }
        this.syscall_blacklist[i] = uint32(nr)
        this.syscall_blacklist_mask |= (1 << i)
    }
    return nil
}

func (this *Filter) SetTidBlacklist(tid_blacklist string) error {
    items := strings.Split(tid_blacklist, ",")
    if len(items) > MAX_COUNT {
        return fmt.Errorf("max tid blacklist count is %d, provided count:%d", MAX_COUNT, len(items))
    }
    for i, v := range items {
        value, _ := strconv.ParseUint(v, 10, 32)
        this.tid_blacklist[i] = uint32(value)
        this.tid_blacklist_mask |= (1 << i)
    }
    return nil
}

func (this *Filter) SetArch(is_32bit bool) {
    if is_32bit {
        this.is_32bit = 1
    } else {
        this.is_32bit = 0
    }
}

func (this *Filter) SetByPass(try_bypass bool) {
    if try_bypass {
        this.try_bypass = 1
    } else {
        this.try_bypass = 0
    }
}

func (this *Filter) SetAfterRead(after_read bool) {
    if after_read {
        this.after_read = 1
    } else {
        this.after_read = 0
    }
}
