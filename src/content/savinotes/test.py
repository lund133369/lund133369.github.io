import os
import re

# Busca `TEXTO` rodeado por exactamente un backtick a izquierda y derecha,
# que no esté rodeado por más backticks.
pattern = re.compile(r'(?<!`)`([^`\n]+?)`(?!`)')

def process_file(filepath):
    with open(filepath, "r", encoding="utf-8") as file:
        content = file.read()

    # Reemplaza `TEXTO` por salto de línea + ```bash TEXTO ``` + salto de línea
    new_content = pattern.sub(r'\n```bash\n \1 \n```\n', content)

    if new_content != content:
        with open(filepath, "w", encoding="utf-8") as file:
            file.write(new_content)
        print(f"✔ Modificado: {filepath}")
    else:
        print(f"– Sin cambios: {filepath}")

def main():
    current_dir = os.getcwd()
    for filename in os.listdir(current_dir):
        if filename.endswith(".md"):
            process_file(os.path.join(current_dir, filename))

if __name__ == "__main__":
    main()
