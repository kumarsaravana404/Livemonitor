import os
import re

with open("security-monitor.html", "r", encoding="utf-8") as f:
    content = f.read()

style_match = re.search(
    r"<style>(.*?)</style>", content, flags=re.DOTALL | re.IGNORECASE
)
css = style_match.group(1).strip() if style_match else ""

script_match = re.search(
    r"<script>(.*?)</script>", content, flags=re.DOTALL | re.IGNORECASE
)
js = script_match.group(1).strip() if script_match else ""

html = re.sub(
    r"<style>.*?</style>",
    '<link rel="stylesheet" href="style.css">',
    content,
    flags=re.DOTALL | re.IGNORECASE,
)
html = re.sub(
    r"<script>.*?</script>",
    '<script src="script.js"></script>',
    html,
    flags=re.DOTALL | re.IGNORECASE,
)

os.makedirs("live_monitor", exist_ok=True)
with open("live_monitor/style.css", "w", encoding="utf-8") as f:
    _ = f.write(css)
with open("live_monitor/script.js", "w", encoding="utf-8") as f:
    _ = f.write(js)
with open("live_monitor/index.html", "w", encoding="utf-8") as f:
    _ = f.write(html)

print("done")
