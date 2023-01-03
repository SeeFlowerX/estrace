package module

import (
	"bytes"
	"context"
	"errors"
	"estrace/app/assets"
	"estrace/app/config"
	"estrace/app/event"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	manager "github.com/ehids/ebpfmanager"
	"golang.org/x/sys/unix"
)

type SymbolInfo struct {
	call_constructors_addr uint64
}

type MapInfo struct {
	name string
	base uint64
	path string
	size uint64
}

type MapsInfo struct {
	soinfos []MapInfo
}

func (this *MapsInfo) ReadProcMaps() error {
	// 读取 /proc/{pid}/maps 解析信息
	return nil
}

func (this *MapsInfo) UpdateMapsInfoByProc() error {
	// 再次读取 /proc/{pid}/maps 更新信息
	return nil
}

func (this *SymbolInfo) ReadSymbolInfo() error {
	// 使用 readelf 获取关键函数信息
	// readelf -s /system/bin/linker | grep call_constructors
	// readelf -s /system/bin/linker64 | grep call_constructors
	// 目标是通过 uprobe 在 call_constructors 这里做信息获取
	// 该函数是在elf刚加载到内存即将调用init之间 这个时候读取 soinfo 传递给前端
	// 便可以在第一时间得到maps信息 并且也不需要频繁读取 /proc/{pid}/maps 了
	return nil
}

func GetSymbolConfig(conf *config.GlobalConfig) (*config.SymbolConfig, error) {
	// 使用 readelf 获取关键函数信息
	// readelf -s /system/bin/linker | grep call_constructors
	// readelf -s /system/bin/linker64 | grep call_constructors
	// 目标是通过 uprobe 在 call_constructors 这里做信息获取
	// 该函数是在elf刚加载到内存即将调用init之间 这个时候读取 soinfo 传递给前端
	// 便可以在第一时间得到maps信息 并且也不需要频繁读取 /proc/{pid}/maps 了
	config := config.SymbolConfig{}
	return &config, nil
}

type MapsModule struct {
	opts              *ebpf.CollectionOptions
	ctx               context.Context
	logger            *log.Logger
	symbolConfig      *config.SymbolConfig
	name              string
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
}

func (this *MapsModule) Init(ctx context.Context, logger *log.Logger, conf *config.GlobalConfig) {
	this.ctx = ctx
	this.logger = logger
	var err error
	this.symbolConfig, err = GetSymbolConfig(conf)
	if err != nil {
		this.logger.Panic("GetSymbolConfig failed")
	}
	this.name = "soinfo"
}

func (this *MapsModule) Stop() error {
	return nil
}

func (this *MapsModule) Name() string {
	return this.name
}

func (this *MapsModule) Close() error {
	return nil
}

func (this *MapsModule) Check() {
	for {
		select {
		case _ = <-this.ctx.Done():
			err := this.Stop()
			if err != nil {
				this.logger.Fatalf("%s\t stop MapsModule error:%v.", this.Name(), err)
			}
			return
		}
	}
}

func (this *MapsModule) Run() error {
	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/stack",
				EbpfFuncName:     "probe_stack",
				AttachToFuncName: this.symbolConfig.Symbol,
				BinaryPath:       this.symbolConfig.Library,
				UprobeOffset:     this.symbolConfig.Offset,
			},
		},

		Maps: []*manager.Map{
			{
				Name: "soinfo_events",
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

	var bpfFileName = filepath.Join("app/bytecode", "soinfo.o")
	byteBuf, err := assets.Asset(bpfFileName)

	if err = this.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), this.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}

	if err = this.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v .", err)
	}

	filterMap, found, err := this.bpfManager.GetMap("filter_map")
	if !found {
		return errors.New("cannot find filter_map")
	}

	filter_key := 0
	filter, err := this.symbolConfig.GetSoInfoFilter()
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
	soinfoEventsMap, found, err := this.bpfManager.GetMap("soinfo_events")
	if !found {
		return errors.New("cannot find soinfo_events map")
	}
	rd, err := perf.NewReader(soinfoEventsMap, os.Getpagesize()*64, false, false)
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader: %s", soinfoEventsMap.String(), err)
		return nil
	}
	go func() {
		for {
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

			var e event.SoInfoDataEvent
			e, err = this.Decode(soinfoEventsMap, record.RawSample)
			if err != nil {
				this.logger.Printf("%s\tthis.child.decode error:%v", this.Name(), err)
				continue
			}
			this.Dispatcher(e)
		}
	}()

	return nil
}

func (this *MapsModule) Decode(em *ebpf.Map, payload []byte) (event event.SoInfoDataEvent, err error) {
	return event, nil
}

func (this *MapsModule) Dispatcher(e event.SoInfoDataEvent) {

}
