from pathlib import Path

path = Path("app.py")

if not path.exists():
    print("ERROR: app.py was not found.")
    print("Open the CyberSage project folder in VS Code first.")
else:
    text = path.read_text(encoding="utf-8")

    replacements = {
        "â€”": "-",
        "â–‹": "_",
        "Â·": "|",
        "â†’": "->",
        "â€¦": "...",
        "â†": "<-",
        "font-family:Segoe UI,Arial,sans-serif":
            'font-family:"Segoe UI",Arial,sans-serif',
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    path.write_text(text, encoding="utf-8")
    print("Done! app.py has been corrected.")