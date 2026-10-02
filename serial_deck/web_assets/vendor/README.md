# Vendored Web UI Assets

The Web dashboard and the pywebview app serve these files from
`/assets/vendor/...` so the UI works without network access. They are exact
copies of the files the dashboard previously loaded from CDNs; nothing was
modified except the added `fonts/fonts.css`. `SHA256SUMS` lists every file.

| Directory | Package | Version | License | Source |
|-----------|---------|---------|---------|--------|
| `tailwindcss/` | Tailwind CSS Play CDN build | 3.4.17 | MIT (`tailwindcss/LICENSE.txt`) | `https://cdn.tailwindcss.com/3.4.17` (what `https://cdn.tailwindcss.com` redirected to on 2026-09-30) |
| `fontawesome/6.4.0/` | Font Awesome Free (CSS + webfonts) | 6.4.0 | Icons CC BY 4.0, fonts SIL OFL 1.1, code MIT (`LICENSE.txt`) | `https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/` |
| `xterm/5.5.0/` | `@xterm/xterm` | 5.5.0 | MIT (`LICENSE.txt`) | `https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/` |
| `xterm-addon-fit/0.10.0/` | `@xterm/addon-fit` | 0.10.0 | MIT (`LICENSE.txt`) | `https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/` |
| `fonts/` | Inter and JetBrains Mono (`@fontsource/inter`, `@fontsource/jetbrains-mono`), latin subset, weights 400/600/700 and 400/700 | 5.3.0 | SIL OFL 1.1 (`LICENSE-Inter.txt`, `LICENSE-JetBrainsMono.txt`) | `https://cdn.jsdelivr.net/npm/@fontsource/...@5.3.0/files/` |

The fonts replace the former Google Fonts stylesheet with the same families
and weights (latin subset only).

To update an asset, download the new version into a new versioned directory,
update the references in `HTML_PAGE` (`serial_deck/web.py`), this table, and
regenerate the checksums:

```bash
cd web_assets/vendor
find . -type f ! -name SHA256SUMS ! -name README.md | sed 's|^\./||' | sort \
    | xargs sha256sum > SHA256SUMS
sha256sum -c SHA256SUMS
```
