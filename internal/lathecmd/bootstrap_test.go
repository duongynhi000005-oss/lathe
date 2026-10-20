package lathecmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lathe-cli/lathe/internal/testutil"
)

func TestRunBootstrapSyncsAndGenerates(t *testing.T) {
	testutil.IsolateGitConfig(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required for bootstrap")
	}

	root := t.TempDir()
	upstream := filepath.Join(root, "upstream")
	writeCodegenFile(t, filepath.Join(upstream, "openapi.yaml"), `openapi: "3.0.3"
paths:
  /users:
    get:
      operationId: Users_List
      tags: [Users]
      summary: List users
      responses:
        "200":
          content:
            application/json:
              schema:
                type: object
`)
	runGit(t, upstream, "init")
	runGit(t, upstream, "add", ".")
	runGit(t, upstream, "-c", "user.name=Lathe", "-c", "user.email=lathe@example.com", "commit", "-m", "initial")
	runGit(t, upstream, "tag", "v1.0.0")

	project := filepath.Join(root, "project")
	testutil.NoError(t, os.MkdirAll(project, 0o755))
	t.Chdir(project)
	writeCodegenFile(t, "go.mod", "module example.com/fake\n\ngo 1.25\n")
	writeCodegenFile(t, "cli.yaml", "cli:\n  name: acmectl\n  short: Acme CLI\n")
	writeCodegenFile(t, "specs/sources.yaml", `sources:
  acme:
    repo_url: `+upstream+`
    pinned_tag: v1.0.0
    backend: openapi3
    openapi3:
      files: [openapi.yaml]
`)

	testutil.NoError(t, RunBootstrap([]string{"-sources", "specs/sources.yaml", "-cache", ".cache"}, &bytes.Buffer{}))

	for _, path := range []string{
		".cache/specs-sync/acme/sync-state.yaml",
		"internal/generated/acme/acme_gen.go",
		"internal/generated/modules_gen.go",
		"skills/acmectl/SKILL.md",
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
	}

	shaOut, err := exec.Command("git", "-C", upstream, "rev-parse", "HEAD").Output()
	testutil.Require(t, err == nil, "git rev-parse: %v", err)
	sha := strings.TrimSpace(string(shaOut))
	modulesGen := readCodegenFile(t, "internal/generated/modules_gen.go")
	moduleRef := readCodegenFile(t, "skills/acmectl/references/modules/acme.md")
	testutil.Require(t, !strings.Contains(modulesGen, upstream), "modules_gen.go leaked upstream path %q:\n%s", upstream, modulesGen)
	testutil.Require(t, !strings.Contains(moduleRef, upstream), "module reference leaked upstream path %q:\n%s", upstream, moduleRef)
	testutil.Require(t, strings.Contains(modulesGen, sha), "modules_gen.go missing resolved sha %q:\n%s", sha, modulesGen)
	testutil.Require(t, strings.Contains(moduleRef, sha), "module reference missing resolved sha %q:\n%s", sha, moduleRef)
}

func TestRunBootstrapLocalPathSyncsAndGenerates(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeCodegenFile(t, "go.mod", "module example.com/fake\n\ngo 1.25\n")
	writeCodegenFile(t, "cli.yaml", "cli:\n  name: acmectl\n  short: Acme CLI\n")
	writeCodegenFile(t, "api/openapi.yaml", `openapi: "3.0.3"
paths:
  /users:
    get:
      operationId: Users_List
      tags: [Users]
      summary: List users
      responses:
        "200":
          content:
            application/json:
              schema:
                type: object
`)
	writeCodegenFile(t, "specs/sources.yaml", `sources:
  acme:
    local_path: ../api
    backend: openapi3
    openapi3:
      files: [openapi.yaml]
`)

	testutil.NoError(t, RunBootstrap([]string{"-sources", "specs/sources.yaml", "-cache", ".cache"}, &bytes.Buffer{}))

	localPath, err := filepath.Abs("api")
	testutil.Require(t, err == nil, "%v", err)
	state, err := os.ReadFile(".cache/specs-sync/acme/sync-state.yaml")
	testutil.Require(t, err == nil, "read sync state: %v", err)
	testutil.Require(t, strings.Contains(string(state), "source_kind: local") && strings.Contains(string(state), "synced_from: "+localPath), "sync state = %s, want local source path %q", state, localPath)
	for _, path := range []string{
		"internal/generated/acme/acme_gen.go",
		"internal/generated/modules_gen.go",
		"skills/acmectl/SKILL.md",
		"skills/acmectl/references/modules/acme.md",
	} {
		data, err := os.ReadFile(path)
		testutil.Require(t, err == nil, "read %s: %v", path, err)
		testutil.Require(t, !strings.Contains(string(data), localPath), "%s encoded local path %q", path, localPath)
	}
	modulesGen := strings.Join(strings.Fields(readCodegenFile(t, "internal/generated/modules_gen.go")), " ")
	testutil.Require(t, strings.Contains(modulesGen, `Kind: "local"`) && strings.Contains(modulesGen, `Reproducible: false`), "modules_gen.go missing local provenance:\n%s", modulesGen)
	moduleRef := readCodegenFile(t, "skills/acmectl/references/modules/acme.md")
	testutil.Require(t, strings.Contains(moduleRef, "Reproducible: no"), "module reference missing local reproducibility:\n%s", moduleRef)

	writeCodegenFile(t, "other/openapi.yaml", `openapi: "3.0.3"
paths: {}
`)
	writeCodegenFile(t, "specs/sources.yaml", `sources:
  acme:
    local_path: ../other
    backend: openapi3
    openapi3:
      files: [openapi.yaml]
`)
	err = runTestCodegen()
	testutil.Require(t, err != nil, "codegen accepted stale local_path cache")
	testutil.Require(t, strings.Contains(err.Error(), "local_path"), "error = %v, want local_path mismatch", err)
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}
