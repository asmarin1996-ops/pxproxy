package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v2.5.0", "v2.5.0", 0},
		{"v2.6.0", "v2.5.0", 1},
		{"v2.5.1", "v2.5.0", 1},
		{"v2.5.0", "v2.6.0", -1},
		{"v10.0.0", "v9.9.9", 1},
		{"2.5.0", "v2.5.0", 0},
		{"v2.5.0-beta", "v2.5.0", 0},
	}
	for _, c := range cases {
		if got := compareSemver(c.a, c.b); got != c.want {
			t.Errorf("compareSemver(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAssetNameForPlatform(t *testing.T) {
	name := AssetNameForPlatform()
	if name == "" {
		t.Fatalf("AssetNameForPlatform devolvio vacio para %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

func TestFindAsset(t *testing.T) {
	rel := &Release{TagName: "v2.6.0", Assets: []Asset{
		{Name: "pxproxy-linux-amd64", Size: 100},
		{Name: "pxproxy-windows-amd64.exe", Size: 200},
	}}
	got, err := FindAsset(rel)
	if err != nil {
		t.Fatalf("FindAsset: %v", err)
	}
	if got.Name == "" {
		t.Fatalf("FindAsset devolvio asset vacio")
	}
	if _, err := FindAsset(&Release{TagName: "v1", Assets: nil}); err == nil {
		t.Fatalf("FindAsset deberia fallar sin assets")
	}
}

// mockRepo levanta un servidor HTTP que simula la API de GitHub de releases y
// la descarga del binario.
func mockRepo(t *testing.T, latestTag string, binary []byte) (options, string) {
	t.Helper()
	asset := AssetNameForPlatform()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases/latest":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"tag_name":"` + latestTag + `","assets":[{"name":"` + asset + `","size":` + itoaT(len(binary)) + `,"browser_download_url":"` + srv.URL + `/download/` + asset + `"}]}`))
		case "/download/pxproxy-windows-amd64.exe", "/download/pxproxy-linux-amd64", "/download/pxproxy-linux-arm64":
			_, _ = w.Write(binary)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	o := options{apiURL: srv.URL + "/releases/latest", client: srv.Client()}
	return o, srv.URL
}

func itoaT(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func TestCheckDiscoversUpdate(t *testing.T) {
	o, _ := mockRepo(t, "v2.6.0", []byte("NEWBINARY"))
	st, err := check(context.Background(), "v2.5.0", o)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !st.UpdateAvailable {
		t.Fatalf("esperaba actualizacion disponible, got %+v", st)
	}
	if st.LatestVersion != "v2.6.0" {
		t.Fatalf("latest=%q, want v2.6.0", st.LatestVersion)
	}
	if st.AssetName == "" {
		t.Fatalf("asset no detectado: %+v", st)
	}
}

func TestCheckNoUpdateWhenCurrent(t *testing.T) {
	o, _ := mockRepo(t, "v2.5.0", []byte("X"))
	st, err := check(context.Background(), "v2.5.0", o)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if st.UpdateAvailable {
		t.Fatalf("no deberia haber actualizacion al estar en la misma version: %+v", st)
	}
}

func TestDownloadAssetWritesBinary(t *testing.T) {
	o, _ := mockRepo(t, "v2.6.0", []byte("PXBINARY-CONTENT"))
	rel, err := fetchLatestRelease(context.Background(), o)
	if err != nil {
		t.Fatalf("fetchLatestRelease: %v", err)
	}
	asset, err := findAssetByName(rel)
	if err != nil {
		t.Fatalf("findAsset: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "pxproxy.update")
	if err := rel.downloadAsset(context.Background(), asset, dest, o); err != nil {
		t.Fatalf("downloadAsset: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("leer descargado: %v", err)
	}
	if string(got) != "PXBINARY-CONTENT" {
		t.Fatalf("contenido descargado = %q", string(got))
	}
}

func TestFetchLatestReleaseMissingRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	o := options{apiURL: srv.URL + "/nope", client: srv.Client()}
	if _, err := fetchLatestRelease(context.Background(), o); err == nil {
		t.Fatalf("esperaba error ante 404")
	}
}
