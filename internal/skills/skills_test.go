package skills_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aspex-security/aspex/internal/skills"
)

func TestFrontmatterAndScripts(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: use-spark\ndescription: >-\n  Access the\n  user's mail.\n---\nRun `spark list`. Docs at https://docs.spark.example/api.\n"), 0o644)
	os.MkdirAll(filepath.Join(dir, "bin"), 0o755)
	os.WriteFile(filepath.Join(dir, "bin", "helper.py"), []byte("print(1)"), 0o644)
	sk, ok := skills.Load(dir, "user")
	if !ok {
		t.Fatal("expected a skill")
	}
	if sk.Name != "use-spark" || sk.Description != "Access the user's mail." {
		t.Errorf("frontmatter: %+v", sk)
	}
	if len(sk.Scripts) != 1 || sk.Scripts[0] != "bin/helper.py" {
		t.Errorf("scripts: %v", sk.Scripts)
	}
	if !sk.Executes || len(sk.Destinations) != 1 || sk.Destinations[0] != "docs.spark.example" {
		t.Errorf("executes/destinations: %+v", sk)
	}
	h1 := sk.ContentHash
	os.WriteFile(filepath.Join(dir, "bin", "helper.py"), []byte("print(2)"), 0o644)
	sk2, _ := skills.Load(dir, "user")
	if sk2.ContentHash == h1 {
		t.Error("changing a script must change the content hash")
	}
}

func TestDirectoryWithoutSkillMdIsNotASkill(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("x"), 0o644)
	if _, ok := skills.Load(dir, "user"); ok {
		t.Error("no SKILL.md means no skill")
	}
	if got := skills.Discover(t.TempDir(), ""); len(got) != 0 {
		t.Errorf("empty home yields no skills, got %v", got)
	}
}
