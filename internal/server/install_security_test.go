package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Flyinsky2004/oh-my-acme/internal/domain"
	"github.com/Flyinsky2004/oh-my-acme/internal/store"
)

func TestInstallCommandPrivateDownloadAndCleanup(t *testing.T) {
	oldVersion := Version
	Version = "v1.2.3"
	t.Cleanup(func() { Version = oldVersion })
	for _, scenario := range []string{"success", "download-failure", "checksum-failure", "installer-failure"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			st, err := store.Open(filepath.Join(dir, "state"))
			if err != nil {
				t.Fatal(err)
			}
			if err := st.WithState(true, func(state *domain.State) error {
				state.Config.ServerHost = "2001:db8::1"
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			installer := "#!/bin/bash\nset -eu\nprintf '%s\\0' \"$@\" > \"$OMA_CAPTURE\"\n[ \"$OMA_SCENARIO\" != installer-failure ]\n"
			installerPath := filepath.Join(dir, "fixture.sh")
			if err := os.WriteFile(installerPath, []byte(installer), 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(installer))
			hash := hex.EncodeToString(sum[:])
			scripts := map[string]string{
				"sudo":   "#!/bin/bash\nset -eu\nexport OMA_ROOT_PHASE=1\nexec \"$@\"\n",
				"mktemp": "#!/bin/bash\nset -eu\n[ \"$OMA_ROOT_PHASE\" = 1 ]\n[ \"$1\" = -d ]\n[ \"$2\" = /tmp/oh-my-acme-agent.XXXXXXXX ]\nmkdir -m 700 \"$OMA_STAGE\"\nprintf '%s\\n' \"$OMA_STAGE\"\n",
				"curl": `#!/bin/bash
set -eu
[ "$OMA_ROOT_PHASE" = 1 ]
[ "$OMA_SCENARIO" != download-failure ] || exit 22
out=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --proto|--proto-redir) [ "$2" = '=https' ]; shift 2 ;;
    -fsSL) shift ;;
    -o) out="$2"; shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\n' "$url" >> "$OMA_URLS"
case "$url" in
  */checksums.txt)
    if [ "$OMA_SCENARIO" = checksum-failure ]; then
      printf '%064d  install-agent.sh\n' 0 > "$out"
    else
      printf '%s  install-agent.sh\n' "$OMA_HASH" > "$out"
    fi ;;
  *) cp "$OMA_INSTALLER" "$out" ;;
esac
`,
				"sha256sum": "#!/bin/bash\nprintf '%s  %s\\n' \"$OMA_HASH\" \"$1\"\n",
			}
			mockBin := filepath.Join(dir, "mock-bin")
			if err := os.Mkdir(mockBin, 0700); err != nil {
				t.Fatal(err)
			}
			for name, script := range scripts {
				if err := os.WriteFile(filepath.Join(mockBin, name), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			capture := filepath.Join(dir, "arguments")
			stage := filepath.Join(dir, "private-stage")
			urls := filepath.Join(dir, "urls")
			name := "节点 ' \" \\ \n$(touch should-not-exist)"
			token := "test-only ' \" \\ \n`false`"
			srv := &Server{cfg: Config{ControlPort: 9444}, st: st, serverLeafFP: "SHA256:" + strings.Repeat("a", 64)}
			command := srv.AgentInstallCommand(name, token)
			if strings.Contains(command, "/tmp/oh-my-acme-agent-install.sh") {
				t.Fatal("predictable temporary file")
			}
			cmd := exec.Command("bash", "-c", command)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(),
				"PATH="+mockBin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"OMA_SCENARIO="+scenario, "OMA_INSTALLER="+installerPath,
				"OMA_CAPTURE="+capture, "OMA_STAGE="+stage, "OMA_HASH="+hash, "OMA_URLS="+urls)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (scenario == "success") {
				t.Fatalf("unexpected result: %v, %s", err, out)
			}
			if _, err := os.Stat(stage); !os.IsNotExist(err) {
				t.Fatalf("stage not removed: %v", err)
			}
			args, readErr := os.ReadFile(capture)
			if scenario == "download-failure" || scenario == "checksum-failure" {
				if !os.IsNotExist(readErr) {
					t.Fatalf("installer executed after failure: %v", readErr)
				}
				return
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
			got := strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")
			want := []string{"-server", "https://[2001:db8::1]:9444", "-token", token, "-ca-fingerprint", srv.serverLeafFP, "-name", name, "-port", "9123", "-version", "v1.2.3"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("arguments changed: %#v", got)
			}
			downloaded, err := os.ReadFile(urls)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(downloaded, []byte("/releases/download/v1.2.3/install-agent.sh")) ||
				!bytes.Contains(downloaded, []byte("/releases/download/v1.2.3/checksums.txt")) {
				t.Fatalf("release not pinned: %s", downloaded)
			}
			if _, err := os.Stat(filepath.Join(dir, "should-not-exist")); !os.IsNotExist(err) {
				t.Fatal("argument executed as code")
			}
		})
	}
}

// TestInstallCommandWithoutSudoRunsDirectly proves the non-sudo variant keeps
// the same download/checksum/cleanup flow without invoking sudo at all. A mock
// sudo that always fails is first on PATH, so any elevation attempt is caught.
func TestInstallCommandWithoutSudoRunsDirectly(t *testing.T) {
	oldVersion := Version
	Version = "v1.2.3"
	t.Cleanup(func() { Version = oldVersion })

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithState(true, func(state *domain.State) error {
		state.Config.ServerHost = "2001:db8::1"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	installer := "#!/bin/bash\nset -eu\nprintf '%s\\0' \"$@\" > \"$OMA_CAPTURE\"\n"
	installerPath := filepath.Join(dir, "fixture.sh")
	if err := os.WriteFile(installerPath, []byte(installer), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(installer))
	hash := hex.EncodeToString(sum[:])
	scripts := map[string]string{
		"sudo":      "#!/bin/bash\necho 'sudo must not be called' >&2\nexit 99\n",
		"mktemp":    "#!/bin/bash\nset -eu\n[ \"$1\" = -d ]\n[ \"$2\" = /tmp/oh-my-acme-agent.XXXXXXXX ]\nmkdir -m 700 \"$OMA_STAGE\"\nprintf '%s\\n' \"$OMA_STAGE\"\n",
		"sha256sum": "#!/bin/bash\nprintf '%s  %s\\n' \"$OMA_HASH\" \"$1\"\n",
		"curl": `#!/bin/bash
set -eu
out=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --proto|--proto-redir) [ "$2" = '=https' ]; shift 2 ;;
    -fsSL) shift ;;
    -o) out="$2"; shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\n' "$url" >> "$OMA_URLS"
case "$url" in
  */checksums.txt) printf '%s  install-agent.sh\n' "$OMA_HASH" > "$out" ;;
  *) cp "$OMA_INSTALLER" "$out" ;;
esac
`,
	}
	mockBin := filepath.Join(dir, "mock-bin")
	if err := os.Mkdir(mockBin, 0700); err != nil {
		t.Fatal(err)
	}
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(mockBin, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	capture := filepath.Join(dir, "arguments")
	stage := filepath.Join(dir, "private-stage")
	urls := filepath.Join(dir, "urls")
	name := "节点 ' \" \\ \n$(touch should-not-exist)"
	token := "test-only ' \" \\ \n`false`"
	srv := &Server{cfg: Config{ControlPort: 9444}, st: st, serverLeafFP: "SHA256:" + strings.Repeat("a", 64)}
	command := srv.AgentInstallCommandWithSudo(name, token, false)
	if strings.HasPrefix(command, "sudo ") {
		t.Fatalf("non-sudo command elevates: %s", command)
	}
	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PATH="+mockBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"OMA_INSTALLER="+installerPath, "OMA_CAPTURE="+capture,
		"OMA_STAGE="+stage, "OMA_HASH="+hash, "OMA_URLS="+urls)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("non-sudo command failed: %v, %s", err, out)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("stage not removed: %v", err)
	}
	args, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")
	want := []string{"-server", "https://[2001:db8::1]:9444", "-token", token, "-ca-fingerprint", srv.serverLeafFP, "-name", name, "-port", "9123", "-version", "v1.2.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("arguments changed: %#v", got)
	}
	downloaded, err := os.ReadFile(urls)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(downloaded, []byte("/releases/download/v1.2.3/install-agent.sh")) ||
		!bytes.Contains(downloaded, []byte("/releases/download/v1.2.3/checksums.txt")) {
		t.Fatalf("release not pinned: %s", downloaded)
	}
	if _, err := os.Stat(filepath.Join(dir, "should-not-exist")); !os.IsNotExist(err) {
		t.Fatal("argument executed as code")
	}
}

// Execute the actual JSON-producing block with hostile strings. Do not run
// the installer entry point, which would touch root-owned services and paths.
func TestInstallScriptsEscapeConfigJSON(t *testing.T) {
	for _, component := range []string{"agent", "server"} {
		t.Run(component, func(t *testing.T) {
			script, err := os.ReadFile(filepath.Join("..", "..", component, "install.sh"))
			if err != nil {
				t.Fatal(err)
			}
			source := string(script)
			start := strings.Index(source, "json_quote() {")
			end := strings.Index(source, "\nREPO=")
			blockStart := strings.Index(source, "  cat > \"${INSTALL_DIR}/config.json\" <<JSON\n")
			if start < 0 || end < start || blockStart < 0 {
				t.Fatal("config generator missing")
			}
			body := source[blockStart:]
			body = body[:strings.Index(body, "\nJSON")+len("\nJSON")]
			body = strings.Replace(body, "  cat > \"${INSTALL_DIR}/config.json\" <<JSON", "cat <<JSON", 1)
			value := "/路径 \" \\ \n\r\t\x01 % $(false) `false`\n"
			code := source[start:end] + "\nset_install_dir \"$1/config.json\"\nSERVER_URL=$1\nNAME=$1\nTOKEN=$1\nCA_FINGERPRINT=$1\nPORT=9123\nWEB_PORT=8080\nCONTROL_PORT=9444\n" + body
			cmd := exec.Command("bash", "-c", code, "test-config", value)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("render: %v: %s", err, out)
			}
			var config map[string]any
			if err := json.Unmarshal(out, &config); err != nil {
				t.Fatalf("invalid JSON: %v: %s", err, out)
			}
			if component == "agent" {
				for _, field := range []string{"server_url", "name", "token", "ca_fingerprint"} {
					if config[field] != value {
						t.Fatalf("%s changed: %#v", field, config[field])
					}
				}
				if config["cert_dir"] != value+"/certs" {
					t.Fatal("path changed")
				}
			} else if config["data_dir"] != value+"/data" || config["pki_dir"] != value+"/pki" {
				t.Fatal("path changed")
			}
		})
	}
}

func TestInstallScriptsRejectPortInjection(t *testing.T) {
	for _, component := range []string{"agent", "server"} {
		for _, port := range []string{"0", "65536", "1,\n\"injected\":true", "-1", "x", "000000000001"} {
			cmd := exec.Command("bash", filepath.Join("..", "..", component, "install.sh"), "-port", port)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "invalid port") {
				t.Fatalf("%s port %q: %v %s", component, port, err, out)
			}
		}
	}
}
