/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func TestPeerProgramManagement(t *testing.T) {
	// Create a device and peer for testing
	tun := tuntest.NewChannelTUN()

	logger := NewLogger(LogLevelVerbose, "")
	device := NewDevice(tun.TUN(), conn.NewDefaultBind(), logger)
	defer device.Close()

	// Generate peer key
	var key NoisePrivateKey
	_, err := rand.Read(key[:])
	if err != nil {
		t.Fatalf("unable to generate private key: %v", err)
	}
	pub := key.publicKey()

	// Create peer
	peer, err := device.NewPeer(pub)
	if err != nil {
		t.Fatalf("failed to create peer: %v", err)
	}

	// Test adding programs
	peer.AddProgram("firefox")
	peer.AddProgram("chrome")
	peer.AddProgram("ssh")

	programs := peer.GetPrograms()
	if len(programs) != 3 {
		t.Errorf("expected 3 programs, got %d", len(programs))
	}

	// Test duplicate addition
	peer.AddProgram("firefox")
	programs = peer.GetPrograms()
	if len(programs) != 3 {
		t.Errorf("expected 3 programs after duplicate add, got %d", len(programs))
	}

	// Test removing program
	peer.RemoveProgram("chrome")
	programs = peer.GetPrograms()
	if len(programs) != 2 {
		t.Errorf("expected 2 programs after removal, got %d", len(programs))
	}

	// Verify removed program is actually gone
	for _, prog := range programs {
		if prog == "chrome" {
			t.Errorf("chrome should have been removed")
		}
	}

	// Test clearing all programs
	peer.ClearPrograms()
	programs = peer.GetPrograms()
	if programs != nil {
		t.Errorf("expected nil after clearing programs, got %v", programs)
	}
}

func TestProgramUAPI(t *testing.T) {
	// Create a test device
	tun := tuntest.NewChannelTUN()

	logger := NewLogger(LogLevelVerbose, "")
	device := NewDevice(tun.TUN(), conn.NewDefaultBind(), logger)
	defer device.Close()

	// Generate keys for configuration
	var key1, key2 NoisePrivateKey
	_, err := rand.Read(key1[:])
	if err != nil {
		t.Fatalf("unable to generate private key: %v", err)
	}
	_, err = rand.Read(key2[:])
	if err != nil {
		t.Fatalf("unable to generate private key: %v", err)
	}
	_, pub2 := key1.publicKey(), key2.publicKey()

	// Set up device with program names
	config := uapiCfg(
		"private_key", hex.EncodeToString(key1[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pub2[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "1.0.0.2/32",
		"replace_allowed_programs", "true",
		"allowed_program", "firefox",
		"allowed_program", "ssh",
		"allowed_program", "curl",
	)

	err = device.IpcSetOperation(strings.NewReader(config))
	if err != nil {
		t.Fatalf("IpcSetOperation failed: %v", err)
	}

	// Verify the programs were set
	peer := device.LookupPeer(pub2)
	if peer == nil {
		t.Fatal("peer not found")
	}

	programs := peer.GetPrograms()
	if len(programs) != 3 {
		t.Errorf("expected 3 programs, got %d", len(programs))
	}

	// Verify program names
	expectedPrograms := map[string]bool{
		"firefox": false,
		"ssh":     false,
		"curl":    false,
	}
	for _, prog := range programs {
		if _, ok := expectedPrograms[prog]; !ok {
			t.Errorf("unexpected program: %s", prog)
		}
		expectedPrograms[prog] = true
	}
	for prog, found := range expectedPrograms {
		if !found {
			t.Errorf("program %s not found", prog)
		}
	}

	// Test IpcGetOperation to verify output
	var output bytes.Buffer
	err = device.IpcGetOperation(&output)
	if err != nil {
		t.Fatalf("IpcGetOperation failed: %v", err)
	}

	outputStr := output.String()
	if !strings.Contains(outputStr, "allowed_program=firefox") {
		t.Error("output should contain allowed_program=firefox")
	}
	if !strings.Contains(outputStr, "allowed_program=ssh") {
		t.Error("output should contain allowed_program=ssh")
	}
	if !strings.Contains(outputStr, "allowed_program=curl") {
		t.Error("output should contain allowed_program=curl")
	}
}

func TestProgramRemovalViaUAPI(t *testing.T) {
	// Create a test device
	tun := tuntest.NewChannelTUN()

	logger := NewLogger(LogLevelVerbose, "")
	device := NewDevice(tun.TUN(), conn.NewDefaultBind(), logger)
	defer device.Close()

	// Generate keys
	var key1, key2 NoisePrivateKey
	_, err := rand.Read(key1[:])
	if err != nil {
		t.Fatalf("unable to generate private key: %v", err)
	}
	_, err = rand.Read(key2[:])
	if err != nil {
		t.Fatalf("unable to generate private key: %v", err)
	}
	_, pub2 := key1.publicKey(), key2.publicKey()

	// Initial config with programs
	config1 := uapiCfg(
		"private_key", hex.EncodeToString(key1[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pub2[:]),
		"protocol_version", "1",
		"allowed_program", "firefox",
		"allowed_program", "ssh",
	)

	err = device.IpcSetOperation(strings.NewReader(config1))
	if err != nil {
		t.Fatalf("IpcSetOperation failed: %v", err)
	}

	peer := device.LookupPeer(pub2)
	if peer == nil {
		t.Fatal("peer not found")
	}

	// Verify initial programs
	programs := peer.GetPrograms()
	if len(programs) != 2 {
		t.Errorf("expected 2 programs initially, got %d", len(programs))
	}

	// Remove one program using negative syntax
	config2 := uapiCfg(
		"public_key", hex.EncodeToString(pub2[:]),
		"allowed_program", "-firefox",
	)

	err = device.IpcSetOperation(strings.NewReader(config2))
	if err != nil {
		t.Fatalf("IpcSetOperation for removal failed: %v", err)
	}

	// Verify program was removed
	programs = peer.GetPrograms()
	if len(programs) != 1 {
		t.Errorf("expected 1 program after removal, got %d", len(programs))
	}
	if programs[0] != "ssh" {
		t.Errorf("expected ssh, got %s", programs[0])
	}

	// Test replace_allowed_programs
	config3 := uapiCfg(
		"public_key", hex.EncodeToString(pub2[:]),
		"replace_allowed_programs", "true",
	)

	err = device.IpcSetOperation(strings.NewReader(config3))
	if err != nil {
		t.Fatalf("IpcSetOperation for replace failed: %v", err)
	}

	// Verify all programs were cleared
	programs = peer.GetPrograms()
	if programs != nil {
		t.Errorf("expected no programs after replace, got %v", programs)
	}
}
