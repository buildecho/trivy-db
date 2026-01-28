package echo_pip

import (
	"embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

//go:embed fixed_versions.json
var fixedVersionsFS embed.FS

type VulnInfo struct {
	FixedVersion string `json:"fixed_version"`
	Severity     string `json:"severity"`
}

type Advisories map[string]VulnInfo

const (
	distroName    = "echo-pip"
	pipBucketName = "pip::ZZZEcho Vulnerability Database"
)

// FixedVersions represents the structure of fixed_versions.json
// Structure: pkgName -> cveID -> []versions
type FixedVersions map[string]map[string][]string

var (
	source = types.DataSource{
		ID:   vulnerability.EchoPip,
		Name: "Echo",
		URL:  "https://advisory.echohq.com/data.json",
	}
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", distroName)
	eb := oops.In(string(source.ID)).With("root_dir", rootDir)

	advisoryMap := make(map[string]Advisories)

	// Read external advisories if the directory exists
	entries, err := os.ReadDir(rootDir)
	if err != nil && !os.IsNotExist(err) {
		return eb.Wrapf(err, "failed to read directory")
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		pkgName, advisories, err := readPackageAdvisories(rootDir, entry.Name())
		if err != nil {
			return eb.With("file_name", entry.Name()).Wrapf(err, "failed to read package advisories")
		}
		advisoryMap[pkgName] = advisories
	}

	if err = vs.save(advisoryMap); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func (vs VulnSrc) save(advisoryMap map[string]Advisories) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, pipBucketName, source); err != nil {
			return oops.Wrapf(err, "failed to put data source")
		}
		for pkgName, advisories := range advisoryMap {
			if err := vs.saveAdvisories(tx, pkgName, advisories); err != nil {
				return oops.Wrapf(err, "failed to save vulnerabilities")
			}
		}

		// Save fixed versions to pip bucket
		if err := vs.saveFixedVersions(tx); err != nil {
			return oops.Wrapf(err, "failed to save fixed versions")
		}

		return nil
	})
	if err != nil {
		return oops.Wrapf(err, "batch update failed")
	}
	return nil
}

func (vs VulnSrc) saveAdvisories(tx *bolt.Tx, pkgName string, advisories Advisories) error {
	for cveID, vulnInfo := range advisories {
		adv := types.Advisory{
			FixedVersion: vulnInfo.FixedVersion,
		}

		if vulnInfo.Severity != "" {
			severity, err := types.NewSeverity(strings.ToUpper(vulnInfo.Severity))
			if err == nil {
				adv.Severity = severity
			}
		}

		if err := vs.dbc.PutAdvisoryDetail(tx, cveID, pkgName, []string{pipBucketName}, adv); err != nil {
			return oops.Wrapf(err, "failed to save advisory detail")
		}

		if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
			return oops.Wrapf(err, "failed to save the vulnerability ID")
		}
	}
	return nil
}

func (vs VulnSrc) saveFixedVersions(tx *bolt.Tx) error {
	// Read embedded fixed_versions.json
	data, err := fixedVersionsFS.ReadFile("fixed_versions.json")
	if err != nil {
		return oops.Wrapf(err, "failed to read fixed_versions.json")
	}

	var fixedVersions FixedVersions
	if err := json.Unmarshal(data, &fixedVersions); err != nil {
		return oops.Wrapf(err, "failed to unmarshal fixed_versions.json")
	}

	// Put data source for pip bucket (already done in save(), but ensure it's set)
	if err := vs.dbc.PutDataSource(tx, pipBucketName, source); err != nil {
		return oops.Wrapf(err, "failed to put pip data source")
	}

	// For each package, create advisory with VulnerableVersions
	for pkgName, cveMap := range fixedVersions {
		for cveID, versions := range cveMap {
			patchedVersions := []string{}
			for _, version := range versions {
				patchedVersions = append(patchedVersions, version)
			}
			adv := types.Advisory{
				PatchedVersions: patchedVersions,
			}

			if err := vs.dbc.PutAdvisoryDetail(tx, cveID, pkgName, []string{pipBucketName}, adv); err != nil {
				return oops.Wrapf(err, "failed to save pip advisory detail")
			}

			if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
				return oops.Wrapf(err, "failed to save the vulnerability ID")
			}
		}
	}

	return nil
}

func (vs VulnSrc) Get(_, pkgName string) ([]types.Advisory, error) {
	eb := oops.In(string(source.ID))

	advisories, err := vs.dbc.GetAdvisories(distroName, pkgName)
	if err != nil {
		return nil, eb.With("bucket", distroName).Wrapf(err, "failed to get advisories")
	}

	return advisories, nil
}

func readPackageAdvisories(rootDir, fileName string) (string, Advisories, error) {
	filePath := filepath.Join(rootDir, fileName)
	pkgName := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	f, err := os.Open(filePath)
	if err != nil {
		return "", nil, oops.Wrapf(err, "failed to open file")
	}
	defer f.Close()

	var advisories Advisories
	if err := json.NewDecoder(f).Decode(&advisories); err != nil {
		return "", nil, oops.Wrapf(err, "json decode error")
	}

	return pkgName, advisories, nil
}
