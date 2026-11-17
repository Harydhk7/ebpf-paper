package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const socketPath = "/tmp/intentguard.sock"

type request struct {
	PID    uint32  `json:"pid"`
	Action string  `json:"action"`
	Policy *policy `json:"policy,omitempty"`
}

type policy struct {
	BlockNetwork uint8 `json:"block_network"`
	BlockExec    uint8 `json:"block_exec"`
}

type response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock rlimit: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("load eBPF objects: %v", err)
	}
	defer objs.Close()

	connectLink, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.HandleConnect, nil)
	if err != nil {
		log.Fatalf("attach connect tracepoint: %v", err)
	}
	defer connectLink.Close()
	execLink, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		log.Fatalf("attach execve tracepoint: %v", err)
	}
	defer execLink.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ring buffer: %v", err)
	}
	defer reader.Close()
	go readEvents(reader)

	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("remove stale socket: %v", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("listen on %s: %v", socketPath, err)
	}
	defer func() {
		listener.Close()
		_ = os.Remove(socketPath)
	}()
	if err := os.Chmod(socketPath, 0600); err != nil {
		log.Fatalf("set socket permissions: %v", err)
	}

	go serve(listener, objs.PolicyMap)
	log.Printf("IntentGuard daemon listening on %s", socketPath)
	waitForSignal()
}

func serve(listener net.Listener, policies *ebpf.Map) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept connection: %v", err)
			continue
		}
		go handleConnection(conn, policies)
	}
}

func handleConnection(conn net.Conn, policies *ebpf.Map) {
	defer conn.Close()
	var req request
	err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req)
	if err == nil {
		err = applyRequest(policies, req)
	}
	resp := response{OK: err == nil}
	if err != nil {
		resp.Error = err.Error()
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

func applyRequest(policies *ebpf.Map, req request) error {
	if req.PID == 0 {
		return errors.New("pid must be positive")
	}
	switch req.Action {
	case "set":
		if req.Policy == nil {
			return errors.New("policy is required for set")
		}
		if req.Policy.BlockNetwork > 1 || req.Policy.BlockExec > 1 {
			return errors.New("policy flags must be 0 or 1")
		}
		return policies.Update(req.PID, bpfPolicyT{
			BlockNetwork: req.Policy.BlockNetwork,
			BlockExec:    req.Policy.BlockExec,
		}, ebpf.UpdateAny)
	case "delete":
		return policies.Delete(req.PID)
	default:
		return fmt.Errorf("unsupported action %q", req.Action)
	}
}

func readEvents(reader *ringbuf.Reader) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("read ring buffer: %v", err)
			continue
		}
		var event bpfEventT
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &event); err != nil {
			log.Printf("decode ring buffer event: %v", err)
			continue
		}
		log.Printf("[ALERT] SIGKILL sent for PID %d (type=%d, comm=%q)",
			event.Pid, event.ViolationType, commString(event.Comm))
	}
}

func commString(comm [16]int8) string {
	name := make([]byte, 0, len(comm))
	for _, char := range comm {
		if char == 0 {
			break
		}
		name = append(name, byte(char))
	}
	return string(name)
}

func waitForSignal() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
}
