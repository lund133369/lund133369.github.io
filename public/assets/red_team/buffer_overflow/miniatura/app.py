from PIL import Image, ImageDraw, ImageFont

def draw_rounded_label(draw, position, text, font, padding=10, radius=10):
    bbox = font.getbbox(text)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]

    x, y = position
    box = [x, y, x + text_width + padding * 3, y + text_height + padding * 3]

    draw.rounded_rectangle(box, radius=radius, fill="white")
    draw.text((x + padding, y + padding-20), text, font=font, fill="black")

def generar_imagenes_enumeradas(base_path, output_base, posicion, cantidad):
    try:
        font = ImageFont.truetype("arial.ttf", size=150)
    except IOError:
        font = ImageFont.load_default()

    for i in range(1, cantidad + 1):
        # Cargar imagen base cada vez
        imagen = Image.open(base_path).convert("RGBA")
        draw = ImageDraw.Draw(imagen)

        etiqueta = f"{i:03}"  # Ej: 001, 002, etc.
        draw_rounded_label(draw, posicion, etiqueta, font)

        output_path = f"{output_base}_{etiqueta}.png"
        imagen.save(output_path)
        print(f"Generada: {output_path}")

# Ejemplo de uso:
generar_imagenes_enumeradas(
    base_path="plantilla.png",
    output_base="miniatura_buffer",  # crea un archivo como salida/imagen_001.png
    posicion=(1400, 1050),  # posición de la etiqueta
    cantidad=30         # número de imágenes a generar
)
