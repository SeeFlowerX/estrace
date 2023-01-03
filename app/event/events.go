package event

type SyscallDataEvent struct {
	DataType  int64  `json:"dataType"`
	Timestamp uint64 `json:"timestamp"`
	Pid       uint32 `json:"pid"`
	Tid       uint32 `json:"tid"`
}

type SoInfoDataEvent struct {
	DataType  int64  `json:"dataType"`
	Timestamp uint64 `json:"timestamp"`
	Pid       uint32 `json:"pid"`
	Tid       uint32 `json:"tid"`
}
