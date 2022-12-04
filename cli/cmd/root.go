package cmd

import (
	"context"
	"errors"
	"estrace/app/config"
	"estrace/app/module"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
)

var global_config = config.NewGlobalConfig()

var rootCmd = &cobra.Command{
	Use:               "estrace",
	Short:             "eBPF on Android案例",
	Long:              "syscall调用追踪",
	PersistentPreRunE: persistentPreRunEFunc,
	Run:               runFunc,
}

// cobra.Command 中几个函数执行的顺序
// PersistentPreRun
// PreRun
// Run
// PostRun
// PersistentPostRun

func runFunc(command *cobra.Command, args []string) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFun := context.WithCancel(context.TODO())

	// 首先根据全局设定设置日志输出
	logger := log.New(os.Stdout, "syscall_", log.Ltime)
	if global_config.LogFile != "" {
		log_path := global_config.ExecPath + "/" + global_config.LogFile
		_, err := os.Stat(log_path)
		if err != nil {
			if os.IsNotExist(err) {
				os.Remove(log_path)
			}
		}
		f, err := os.Create(log_path)
		if err != nil {
			logger.Fatal(err)
			os.Exit(1)
		}
		if global_config.Quiet {
			// 直接设置 则不会输出到终端
			logger.SetOutput(f)
		} else {
			// 这样可以同时输出到终端
			mw := io.MultiWriter(os.Stdout, f)
			logger.SetOutput(mw)
		}
	}

	var runMods uint8
	var wg sync.WaitGroup

	mod := &module.Module{}

	mod.Init(ctx, logger, global_config)
	err := mod.Run()
	if err != nil {
		logger.Printf("%s\tmodule Run failed, [skip it]. error:%+v", mod.Name(), err)
		os.Exit(1)
	}
	if global_config.Debug {
		logger.Printf("%s\tmodule started successfully", mod.Name())
	}
	wg.Add(1)
	runMods++

	if runMods > 0 {
		logger.Printf("start %d modules", runMods)
		<-stopper
	} else {
		logger.Println("No runnable modules, Exit(1)")
		os.Exit(1)
	}
	cancelFun()

	err = mod.Close()
	logger.Println("mod Close")
	wg.Done()
	if err != nil {
		logger.Fatalf("%s:module close failed. error:%+v", mod.Name(), err)
	}

	wg.Wait()
	os.Exit(0)
}
func persistentPreRunEFunc(command *cobra.Command, args []string) error {
	// 如果设置了包名 那就尝试从包名中解析到uid

	exec_path, err := os.Executable()
	if err != nil {
		return fmt.Errorf("please build as executable binary, %v", err)
	}
	global_config.ExecPath = path.Dir(exec_path)

	if global_config.Name == "" && global_config.Uid == 0 {
		return errors.New("please set --uid or --name")
	}
	if global_config.Name != "" {
		if err = parseByPackage(global_config.Name); err != nil {
			return err
		}
	}
	if global_config.Uid == 0 {
		return errors.New("Opps cannot get correct uid config, set --uid plz")
	}
	return nil
}

func runCommand(executable string, args ...string) (string, error) {
	cmd := exec.Command(executable, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	bytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		return "", err
	}
	if err := cmd.Wait(); err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytes)), nil
}

func parseByPackage(name string) error {
	// 先设置默认值
	global_config.Is32Bit = true
	// 先检查dumpsys命令 如果没有可能是eadb环境
	// 那么只能用ps获取正在运行的APP包名
	result, err := runCommand("which", "dumpsys")
	if err != nil {
		return err
	}
	if result == "" {
		fmt.Println("dumpsys not exists, try ps now ...")
		result, err = runCommand("ps", "-ef", "|", "grep", name+"$")
		if err != nil {
			return err
		}
		if result != "" {
			parts := strings.SplitN(result, " ", 1)
			global_config.Uid, _ = strconv.ParseUint(parts[0], 10, 64)
		} else {
			return fmt.Errorf("can not use ps to find uid by package name:%s, set --uid plz", name)
		}
	} else {
		result, err := runCommand("dumpsys", "package", name)
		if err != nil {
			return err
		}
		has_uid := false
		for _, line := range strings.Split(result, "\n") {
			line = strings.Trim(line, " ")
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key, value := parts[0], parts[1]
				switch key {
				case "userId":
					global_config.Uid, _ = strconv.ParseUint(value, 10, 64)
					has_uid = true
					break
				case "primaryCpuAbi":
					if value == "arm64-v8a" {
						global_config.Is32Bit = false
					}
					break
				}
			}
		}
		if !has_uid {
			return fmt.Errorf("can not use dumpsys to find uid by package name:%s, set --uid plz", name)
		}
	}

	return nil
}

func Execute() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.EnablePrefixMatching = true
	rootCmd.PersistentFlags().StringVarP(&global_config.Name, "name", "n", "", "must set uid or package name")
	rootCmd.PersistentFlags().Uint64VarP(&global_config.Uid, "uid", "u", 0, "must set uid or package name")
	rootCmd.PersistentFlags().Uint64VarP(&global_config.Pid, "pid", "p", 0, "add pid to filter")
	rootCmd.PersistentFlags().StringVarP(&global_config.SysCall, "syscall", "s", "", "add syscall name to whitelist filter")
	rootCmd.PersistentFlags().StringVarP(&global_config.NoSysCall, "no-syscall", "", "", "add syscall name to blacklist filter")
	rootCmd.PersistentFlags().StringVarP(&global_config.NoTid, "no-tid", "", "", "add tid to blacklist filter")
	rootCmd.PersistentFlags().StringVarP(&global_config.LogFile, "out", "o", "", "save the log to file")
	rootCmd.PersistentFlags().BoolVarP(&global_config.NoUidFilter, "no-uid-filter", "", false, "ignore uid filter")
	rootCmd.PersistentFlags().BoolVarP(&global_config.Bypass, "bypass", "", false, "try bypass root check")
	rootCmd.PersistentFlags().BoolVarP(&global_config.GetLR, "getlr", "", false, "try get lr info")
	rootCmd.PersistentFlags().BoolVarP(&global_config.GetPC, "getpc", "", false, "try get pc info")
	rootCmd.PersistentFlags().BoolVarP(&global_config.Debug, "debug", "d", false, "enable debug logging")
	rootCmd.PersistentFlags().BoolVarP(&global_config.Quiet, "quiet", "q", false, "wont logging to terminal when used")
}
