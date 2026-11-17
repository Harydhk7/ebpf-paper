package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type policy_t -type event_t bpf ../bpf/intentguard.bpf.c
