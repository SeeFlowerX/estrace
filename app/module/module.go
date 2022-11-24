package module

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"estrace/app/assets"
	"estrace/app/config"
	"estrace/app/event"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	manager "github.com/ehids/ebpfmanager"
	"golang.org/x/sys/unix"
)

type Module struct {
	opts              *ebpf.CollectionOptions
	ctx               context.Context
	logger            *log.Logger
	conf              *config.GlobalConfig
	name              string
	systable_config   config.SysTableConfig
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
}

func (this *Module) Init(ctx context.Context, logger *log.Logger, conf *config.GlobalConfig) {
	this.ctx = ctx
	this.logger = logger
	this.conf = conf
	this.name = "syscall"
}

func (this *Module) Stop() error {
	return nil
}

func (this *Module) Name() string {
	return this.name
}

func (this *Module) Close() error {
	return nil
}

func (this *Module) Check() {
	for {
		select {
		case _ = <-this.ctx.Done():
			err := this.Stop()
			if err != nil {
				this.logger.Fatalf("%s\t stop Module error:%v.", this.Name(), err)
			}
			return
		}
	}
}

func (this *Module) Run() error {
	var table_path string
	if this.conf.Is32Bit {
		table_path = "app/config/table32.json"
	} else {
		table_path = "app/config/table64.json"
	}
	this.systable_config = config.NewSysTableConfig()
	// 获取syscall读取参数的mask配置
	table_buffer, err := assets.Asset(table_path)
	var tmp_config map[string][]interface{}
	json.Unmarshal(table_buffer, &tmp_config)
	for nr, config_arr := range tmp_config {
		table_config := config.TableConfig{
			Count: uint32(config_arr[0].(float64)),
			Name:  config_arr[1].(string),
			Mask:  uint32(config_arr[2].(float64)),
		}
		this.systable_config[nr] = table_config
	}

	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:      "raw_tracepoint/sys_enter",
				EbpfFuncName: "raw_syscalls_sys_enter",
			},
			{
				Section:      "raw_tracepoint/sys_exit",
				EbpfFuncName: "raw_syscalls_sys_exit",
			},
		},

		Maps: []*manager.Map{
			{
				Name: "syscall_events",
			},
		},
	}
	this.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	// 从assets中获取eBPF程序的二进制数据
	var bpfFileName = filepath.Join("app/bytecode", "raw_syscalls.o")
	// this.logger.Printf("%s\tBPF bytecode filename:%s\n", this.Name(), bpfFileName)
	byteBuf, err := assets.Asset(bpfFileName)

	// 初始化 bpfManager
	if err = this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}

	// 启动 bpfManager
	if err = this.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v .", err)
	}
	// 更新map中的配置
	argMaskMap, found, err := this.bpfManager.GetMap("arg_mask_map")
	if !found {
		return errors.New("cannot find arg_mask_map")
	}
	for nr, table_config := range this.systable_config {
		// 更新用于获取字符串信息的map
		nr_key, _ := strconv.ParseUint(nr, 10, 32)
		argMaskMap.Update(unsafe.Pointer(&nr_key), unsafe.Pointer(&table_config.Mask), ebpf.UpdateAny)
	}

	archMap, found, err := this.bpfManager.GetMap("arch_map")
	if !found {
		return errors.New("cannot find arch_map")
	}

	// 更新进程架构信息
	arch_key := 0
	arch := this.conf.GetArch()
	archMap.Update(unsafe.Pointer(&arch_key), unsafe.Pointer(&arch), ebpf.UpdateAny)

	filterMap, found, err := this.bpfManager.GetMap("filter_map")
	if !found {
		return errors.New("cannot find filter_map")
	}
	// 更新进程过滤设置
	filter_key := 0
	filter := this.conf.GetFilter()
	if this.conf.SysCall != "" {
		taget_nr, err := this.systable_config.GetNR(this.conf.SysCall)
		if err != nil {
			return err
		}
		filter.UpdateNR(uint32(taget_nr))
	}
	err = this.systable_config.CheckNR(filter.GetNR())
	if err != nil {
		return err
	}
	filterMap.Update(unsafe.Pointer(&filter_key), unsafe.Pointer(&filter), ebpf.UpdateAny)

	var errChan = make(chan error, 8)
	// 随时记录读取事件过程中的异常情况
	go func() {
		for {
			select {
			case err := <-errChan:
				this.logger.Printf("%s\treadEvents error:%v", this.Name(), err)
			}
		}
	}()
	//  开始读取数据
	syscallEventsMap, found, err := this.bpfManager.GetMap("syscall_events")
	if !found {
		return errors.New("cannot find syscall_events map")
	}
	// rd, err := perf.NewReader(syscallEventsMap, os.Getpagesize()*64)
	rd, err := perf.NewReader(syscallEventsMap, os.Getpagesize()*64, false, false)
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader: %s", syscallEventsMap.String(), err)
		return nil
	}
	go func() {
		for {
			// 先判断ctx正不正常
			select {
			case _ = <-this.ctx.Done():
				this.logger.Printf("%s\tperfEventReader received close signal from context.Done().", this.Name())
				return
			default:
			}

			record, err := rd.Read()

			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				errChan <- fmt.Errorf("%s\treading from perf event reader: %s", this.Name(), err)
				return
			}

			if record.LostSamples != 0 {
				this.logger.Printf("%s\tperf event ring buffer full, dropped %d samples", this.Name(), record.LostSamples)
				continue
			}

			var e event.SyscallDataEvent
			// 读取到事件数据之后 立刻开始解析获取结果
			e, err = this.Decode(syscallEventsMap, record.RawSample)
			if err != nil {
				this.logger.Printf("%s\tthis.child.decode error:%v", this.Name(), err)
				continue
			}

			// 事件数据解析完成之后上报数据，比如写入日志获取输出到特定格式文件中
			this.Dispatcher(e)
		}
	}()

	return nil
}

type syscall_data struct {
	pid        uint32
	tid        uint32
	mtype      uint32
	syscall_id uint32
	lr         uint64
	sp         uint64
	pc         uint64
	ret        uint64
	arg_index  uint64
	args       [6]uint64
	comm       [16]byte
	arg_str    [256]byte
}

func (this *Module) Decode(em *ebpf.Map, payload []byte) (event event.SyscallDataEvent, err error) {
	data := &syscall_data{}
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &data.pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &data.tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &data.mtype); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &data.syscall_id); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &data.lr); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &data.sp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &data.pc); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &data.ret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &data.arg_index); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &data.args); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &data.comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &data.arg_str); err != nil {
		return
	}
	base_str := fmt.Sprintf("[%s] type:%d pid:%d tid:%d nr:%s", bytes.TrimSpace(bytes.Trim(data.comm[:], "\x00")), data.mtype, data.pid, data.tid, this.ReadNR(*data))
	switch data.mtype {
	case 1:
		if this.conf.GetLR {
			info, err := this.ParseLR(*data)
			if err != nil {
				this.logger.Printf("ParseLR err:%v\n", err)
			}
			this.logger.Printf("%s %s LR:%s\n", base_str, this.ReadArgs(*data), info)
		} else {
			this.logger.Printf("%s %s\n", base_str, this.ReadArgs(*data))
		}
	case 2:
		this.logger.Printf("%s arg_index:%d arg_str:%s\n", base_str, data.arg_index, bytes.TrimSpace(bytes.Trim(data.arg_str[:], "\x00")))
	case 3:
		this.logger.Printf("%s ret:0x%x\n", base_str, data.ret)
	}

	return event, nil
}

func (this *Module) ReadNR(data syscall_data) string {
	config := this.systable_config[fmt.Sprintf("%d", data.syscall_id)]
	return config.Name
}

func (this *Module) ParseLR(data syscall_data) (string, error) {
	info := "UNKNOWN"
	// 直接读取maps信息 计算lr在什么地方 定位syscall调用也就一目了然了
	filename := fmt.Sprintf("/proc/%d/maps", data.pid)
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return info, fmt.Errorf("Error when opening file:%v", err)
	}
	var (
		seg_start  uint64
		seg_end    uint64
		permission string
		seg_offset uint64
		device     string
		inode      uint64
		seg_path   string
	)
	for _, line := range strings.Split(string(content), "\n") {
		reader := strings.NewReader(line)
		n, err := fmt.Fscanf(reader, "%x-%x %s %x %s %d %s", &seg_start, &seg_end, &permission, &seg_offset, &device, &inode, &seg_path)
		if err == nil && n == 7 {
			if data.lr >= seg_start && data.lr < seg_end {
				offset := seg_offset + (data.lr - seg_start)
				info = fmt.Sprintf("%s + 0x%x", seg_path, offset)
				break
			}
		}
	}
	return info, err
}

func (this *Module) ReadArgs(data syscall_data) string {
	config := this.systable_config[fmt.Sprintf("%d", data.syscall_id)]
	regs := make(map[string]string)
	for i := 0; i < int(config.Count); i++ {
		regs[fmt.Sprintf("x%d", i)] = fmt.Sprintf("0x%x", data.args[i])
	}
	regs["lr"] = fmt.Sprintf("0x%x", data.lr)
	regs["sp"] = fmt.Sprintf("0x%x", data.sp)
	regs["pc"] = fmt.Sprintf("0x%x", data.pc)
	regs_info, err := json.Marshal(regs)
	if err != nil {
		regs_info = make([]byte, 0)
	}
	return string(regs_info)
}

func (this *Module) Dispatcher(e event.SyscallDataEvent) {

}
