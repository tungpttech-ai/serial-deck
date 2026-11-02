#!/bin/sh
# Regenerate the dashboard CSS after changing Tailwind classes in serial_deck/*.py.
cd "$(dirname "$0")/.." && exec npx --yes tailwindcss@3.4.17 -c tools/tailwind.config.js \
  -i tools/tailwind.in.css -o serial_deck/web_assets/tailwind.css --minify
