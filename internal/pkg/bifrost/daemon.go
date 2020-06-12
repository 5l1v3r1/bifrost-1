package bifrost

import (
	"fmt"
	"github.com/ClessLi/go-nginx-conf-parser/pkg/resolv"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
)

// DONE: 编写biforst守护进程
// DONE: 修复Restart函数启动bifrost失败的bug
func Start() error {
	if os.Getppid() != 1 {
		// 执行子进程
		execPath, pathErr := filepath.Abs(os.Args[0])
		if pathErr != nil {
			return pathErr
		}

		args := append([]string{ex}, os.Args[1:]...)

		// 判断是否已存在子进程
		if pid, pidErr := getPid(); pidErr == nil {

			process, procErr := os.FindProcess(pid)
			if procErr != nil {
				return procErr
			}

			return fmt.Errorf("bifrost <PID %d> is running", process.Pid)
		} else if pidErr != procStatusNotRunning {
			return pidErr
		}

		// 启动子进程
		Log(NOTICE, fmt.Sprintf("starting bifrost..."))
		os.Stdout = Stdoutf
		os.Stderr = Stdoutf
		_, procErr := os.StartProcess(execPath, args, &os.ProcAttr{
			Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		})
		if procErr != nil {
			return procErr
		}

		return nil
	} else {
		// 执行bifrost进程

		// 记录pid
		pid := os.Getpid()
		pidErr := ioutil.WriteFile(pidFile, []byte(fmt.Sprintf("%d", pid)), 644)
		if pidErr != nil {
			return pidErr
		}

		// 启动bifrost进程
		Log(NOTICE, fmt.Sprintf("bifrost <PID %d> is started", pid))
		// TODO: 并发异常，只能同时运行一个配置接口，待优化
		for _, ngConfig := range Configs.NGConfigs {
			ng, err := resolv.Load(ngConfig.ConfPath)

			if err != nil {
				fmt.Println(err)
				continue
			}

			errChan := make(chan error)

			go Run(&ngConfig, ng, errChan)

			err = <-errChan
			if err != nil {
				Log(CRITICAL, fmt.Sprintf("%s's coroutine has been stoped. Cased by '%s'", ngConfig.Name, err))
			} else {
				Log(NOTICE, fmt.Sprintf("%s's coroutine has been stoped", ngConfig.Name))
			}
		}
		stat := fmt.Sprintf("bifrost <PID %d> is finished", pid)
		Log(NOTICE, stat)
		return fmt.Errorf(stat)
	}
}

func Stop() error {
	pid, pidErr := getPid()
	if pidErr != nil {
		return pidErr
	}
	process, procErr := os.FindProcess(pid)
	if procErr != nil {
		Log(ERROR, procErr.Error())
		return procErr
	}

	killErr := process.Kill()
	if killErr != nil {
		if sysErr, ok := killErr.(*os.SyscallError); !ok || sysErr.Syscall != "TerminateProcess" {
			Log(ERROR, killErr.Error())
			return killErr
		} else if ok && sysErr.Syscall == "TerminateProcess" {
			Log(NOTICE, "bifrost is stopping or stopped")
		}
	}

	rmPidFileErr := os.Remove(pidFile)
	if rmPidFileErr != nil {
		Log(ERROR, rmPidFileErr.Error())
		return rmPidFileErr
	}
	Log(NOTICE, "bifrost.pid is removed, bifrost is finished")

	return nil
}

func getPid() (int, error) {
	if _, err := os.Stat(pidFile); err == nil || os.IsExist(err) {
		pidBytes, readPidErr := readFile(pidFile)
		if readPidErr != nil {
			Log(ERROR, readPidErr.Error())
			return -1, readPidErr
		}

		pid, toIntErr := strconv.Atoi(string(pidBytes))
		if toIntErr != nil {
			Log(ERROR, toIntErr.Error())
			return -1, toIntErr
		}

		return pid, nil
	} else {
		return -1, procStatusNotRunning
	}
}

func Restart() error {
	if os.Getppid() != 1 {
		Log(NOTICE, "stopping bifrost...")
		if err := Stop(); err != nil {
			Log(ERROR, fmt.Sprintf("stop bifrost failed cased by: '%s'", err.Error()))
			return err
		}
		return Start()
	} else {
		// 传参给子进程重启时，不重启
		return Start()
	}
}

func Status() (int, error) {
	pid, pidErr := getPid()
	if pidErr != nil {
		return -1, pidErr
	}
	_, procErr := os.FindProcess(pid)
	return pid, procErr
}
