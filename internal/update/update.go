// Package update implementa la auto-actualizacion de pxproxy desde las
// releases publicas del repositorio de GitHub.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	repo      = "asmarin1996/pxproxy"
	apiLatest = "https://api.github.com/repos/" + repo + "/releases/latest"
	// releaseURLTemplate usa el tag para formar la URL del asset binario.
	releaseURLTemplate = "https://github.com/" + repo + "/releases/download/%s/%s"
	defaultTimeout     = 45 * time.Second
)

// Release describe la respuesta de la API de GitHub para la release mas reciente.
type Release struct {
	TagName string  `json:"tag_name"`
	Name    string  `json:"name"`
	Body    string  `json:"body"`
	Assets  []Asset `json:"assets"`
	Draft   bool    `json:"draft"`
	Prerelease bool `json:"prerelease"`
}

// Asset describe un archivo adjunto a la release.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// State es el resultado de una comprobacion de versiones.
type State struct {
	InstalledVersion string `json:"installed_version"`
	LatestVersion    string `json:"latest_version"`
	UpdateAvailable  bool   `json:"update_available"`
	AssetName        string `json:"asset_name"`
	AssetSize        int64  `json:"asset_size"`
	ReleaseURL       string `json:"release_url"`
	Err              string `json:"error,omitempty"`
}

// AssetNameForPlatform devuelve el nombre del binario publicado para la
// plataforma actual del proceso.
func AssetNameForPlatform() string {
	switch {
	case runtime.GOOS == "windows" && runtime.GOARCH == "amd64":
		return "pxproxy-windows-amd64.exe"
	case runtime.GOOS == "linux" && runtime.GOARCH == "amd64":
		return "pxproxy-linux-amd64"
	case runtime.GOOS == "linux" && runtime.GOARCH == "arm64":
		return "pxproxy-linux-arm64"
	}
	return ""
}

func httpClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

// options agrupa parametros inyectables para testing (URL de la API y cliente HTTP).
type options struct {
	apiURL string
	client *http.Client
}

func defaultOptions() options {
	return options{apiURL: apiLatest, client: httpClient(defaultTimeout)}
}

// githubRequest crear la peticion a la API de GitHub con el User-Agent
// requerido por GitHub y el Accept adecuado.
func githubRequest(ctx context.Context, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "pxproxy-updater/1.0")
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

// FetchLatestRelease consulta la release mas reciente publicada.
func FetchLatestRelease(ctx context.Context) (*Release, error) {
	return fetchLatestRelease(ctx, defaultOptions())
}

func fetchLatestRelease(ctx context.Context, o options) (*Release, error) {
	req, err := githubRequest(ctx, o.apiURL)
	if err != nil {
		return nil, err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("API de GitHub devolvio %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("no se encontro ninguna release publicada")
	}
	return &rel, nil
}

// FindAsset busca el binario de la plataforma actual entre los assets de la release.
func FindAsset(rel *Release) (*Asset, error) {
	return findAssetByName(rel)
}

func findAssetByName(rel *Release) (*Asset, error) {
	want := AssetNameForPlatform()
	if want == "" {
		return nil, fmt.Errorf("no hay binario publicado para %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	for i := range rel.Assets {
		if rel.Assets[i].Name == want {
			return &rel.Assets[i], nil
		}
	}
	return nil, fmt.Errorf("la release %s no incluye el binario %q", rel.TagName, want)
}

// compareSemver compara dos versiones semver (vX.Y.Z). Devuelve 1 si a>b,
// -1 si a<b y 0 si son iguales. Ignora componentes no numericos.
func compareSemver(a, b string) int {
	pa, ba := parseSemver(a)
	pb, bb := parseSemver(b)
	if ba != bb {
		if ba {
			return 1
		}
		return -1
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] > pb[i] {
				return 1
			}
			return -1
		}
	}
	return 0
}

func parseSemver(v string) ([3]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" {
		return [3]int{}, false
	}
	parts := strings.SplitN(v, "-", 2)[0]
	nums := strings.Split(parts, ".")
	var out [3]int
	valid := true
	for i := 0; i < 3; i++ {
		if i < len(nums) {
			if n, err := strconv.Atoi(nums[i]); err == nil {
				out[i] = n
			} else {
				valid = false
			}
		}
	}
	return out, valid
}

// Check consulta la ultima version disponible y la compara con la instalada.
// installed es la version actual del binario (p.ej. "v2.5.0"). Cuando el modo
// dev usa versiones como "dev" o "ci-...", se asume que la actualizacion esta
// disponible si hay una release con version semver valida.
func Check(ctx context.Context, installed string) (State, error) {
	return check(ctx, installed, defaultOptions())
}

func check(ctx context.Context, installed string, o options) (State, error) {
	rel, err := fetchLatestRelease(ctx, o)
	if err != nil {
		return State{InstalledVersion: installed, Err: err.Error()}, err
	}
	st := State{
		InstalledVersion: installed,
		LatestVersion:    rel.TagName,
		ReleaseURL:       "https://github.com/" + repo + "/releases/tag/" + rel.TagName,
	}
	if st.LatestVersion != "" && !strings.HasPrefix(st.LatestVersion, "v") {
		st.LatestVersion = "v" + st.LatestVersion
	}
	if a, aerr := findAssetByName(rel); aerr == nil {
		st.AssetName = a.Name
		st.AssetSize = a.Size
	}
	_, builtinSemver := parseSemver(installed)
	if !builtinSemver || compareSemver(st.LatestVersion, installed) > 0 {
		st.UpdateAvailable = true
	}
	return st, nil
}

// DownloadAsset descarga el asset binario de la release a un archivo temporal.
func (rel *Release) DownloadAsset(ctx context.Context, a *Asset, dest string) error {
	return rel.downloadAsset(ctx, a, dest, defaultOptions())
}

func (rel *Release) downloadAsset(ctx context.Context, a *Asset, dest string, o options) error {
	url := a.BrowserDownloadURL
	if url == "" {
		url = fmt.Sprintf(releaseURLTemplate, rel.TagName, a.Name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "pxproxy-updater/1.0")
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("descarga devolvio %d", resp.StatusCode)
	}
	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, werr := io.Copy(f, resp.Body)
	cerr := f.Close()
	if werr != nil {
		os.Remove(tmp)
		return werr
	}
	if cerr != nil {
		os.Remove(tmp)
		return cerr
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return err
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(dest, 0o755)
	}
	return nil
}

// currentExecutable devuelve la ruta absoluta del binario en ejecucion
// (excluyendo la version descargada como temp, devolviendo el .bak previo si
// fuese necesario).
func currentExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return "", err
	}
	if !strings.Contains(exe, ".part") && !strings.Contains(exe, ".update") {
		return exe, nil
	}
	return exe, nil
}

// Apply descarga la ultima release y reemplaza el binario actual, dejando una
// copia de seguridad con sufijo .bak. Devuelve la ruta del binario instalado y
// un mensaje de reinicio.
func Apply(ctx context.Context, installed string) (string, error) {
	return apply(ctx, defaultOptions())
}

func apply(ctx context.Context, o options) (string, error) {
	rel, err := fetchLatestRelease(ctx, o)
	if err != nil {
		return "", err
	}
	asset, err := findAssetByName(rel)
	if err != nil {
		return "", err
	}
	exe, err := currentExecutable()
	if err != nil {
		return "", err
	}
	if exe == "" {
		return "", fmt.Errorf("no se pudo determinar el ejecutable en uso")
	}
	dir := filepath.Dir(exe)
	tmp := filepath.Join(dir, "pxproxy.update")
	if err := rel.downloadAsset(ctx, asset, tmp, o); err != nil {
		return "", err
	}
	backup := exe + ".bak"
	if _, serr := os.Stat(exe); serr == nil {
		_ = os.Remove(backup)
		if rerr := os.Rename(exe, backup); rerr != nil {
			os.Remove(tmp)
			return "", rerr
		}
	}
	if rerr := os.Rename(tmp, exe); rerr != nil {
		// Revertir el backup a su lugar.
		if _, s2 := os.Stat(backup); s2 == nil {
			_ = os.Rename(backup, exe)
		}
		os.Remove(tmp)
		return "", rerr
	}
	return exe, nil
}
