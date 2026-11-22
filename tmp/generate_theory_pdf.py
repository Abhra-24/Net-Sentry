from pathlib import Path
import re
import textwrap

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "PROJECT_THEORY.md"
OUTPUT = ROOT / "PROJECT_THEORY.pdf"
PAGE_W, PAGE_H = 595, 842
LEFT, RIGHT, TOP, BOTTOM = 58, 58, 68, 52

def clean_inline(value):
    value = re.sub(r"`([^`]*)`", r"\1", value)
    value = re.sub(r"\*\*(.*?)\*\*", r"\1", value)
    return value

def parse_blocks(markdown):
    blocks = []
    paragraph = []
    def flush():
        if paragraph:
            blocks.append(("body", clean_inline(" ".join(paragraph).strip())))
            paragraph.clear()
    for raw in markdown.splitlines():
        line = raw.strip()
        if not line:
            flush()
        elif line.startswith("# "):
            flush(); blocks.append(("title", line[2:].strip()))
        elif line.startswith("## "):
            flush(); blocks.append(("heading", line[3:].strip()))
        elif line.startswith("### "):
            flush(); blocks.append(("subheading", line[4:].strip()))
        elif re.match(r"^[-*]\s+", line):
            flush(); blocks.append(("bullet", clean_inline(re.sub(r"^[-*]\s+", "", line))))
        else:
            paragraph.append(line)
    flush()
    return blocks

def wrap(text, size, width, indent=0):
    char_width = size * 0.50
    limit = max(20, int((width - indent) / char_width))
    return textwrap.wrap(text, width=limit, break_long_words=False, break_on_hyphens=False) or [""]

def make_pages(blocks):
    pages, current, y = [], [], PAGE_H - TOP
    for kind, text in blocks:
        if kind == "title": size, font, color, indent, before, after = 23, "F2", (0.06,0.24,0.25), 0, 0, 20
        elif kind == "heading": size, font, color, indent, before, after = 14, "F2", (0.06,0.32,0.32), 0, 13, 8
        elif kind == "subheading": size, font, color, indent, before, after = 11, "F2", (0.12,0.28,0.30), 0, 9, 4
        elif kind == "bullet": size, font, color, indent, before, after = 10, "F1", (0.16,0.19,0.20), 13, 0, 5
        else: size, font, color, indent, before, after = 10, "F1", (0.16,0.19,0.20), 0, 0, 8
        lines = wrap(text, size, PAGE_W - LEFT - RIGHT, indent)
        leading = size * (1.42 if kind in ("body", "bullet") else 1.24)
        need = before + len(lines) * leading + after
        if y - need < BOTTOM + 20 and current:
            pages.append(current); current=[]; y=PAGE_H-TOP
        y -= before
        for i, line in enumerate(lines):
            current.append((line, size, font, color, indent + (8 if kind == "bullet" and i else 0), y))
            y -= leading
        y -= after
    if current: pages.append(current)
    return pages

def pdf_escape(text):
    return text.encode("cp1252", "replace").decode("cp1252").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

def stream_for(rows, page_num, total):
    out = ["0.87 0.91 0.89 RG 58 42 m 537 42 l S", "BT /F1 8 Tf 58 28 Td (NetSentry Project Theory) Tj ET"]
    label = f"Page {page_num} of {total}"
    out.append(f"BT /F1 8 Tf 480 28 Td ({label}) Tj ET")
    for text, size, font, color, indent, y in rows:
        r,g,b=color
        x=LEFT+indent
        if font == "F2" and size == 14:
            out.append(f"0.10 0.52 0.48 RG 58 {y-4:.1f} m 537 {y-4:.1f} l S")
        out.append(f"{r:.3f} {g:.3f} {b:.3f} rg BT /{font} {size} Tf {x:.1f} {y:.1f} Td ({pdf_escape(text)}) Tj ET")
        if indent == 13:
            out.append(f"0.10 0.52 0.48 rg BT /F2 10 Tf {LEFT} {y:.1f} Td (\267) Tj ET")
    return "\n".join(out).encode("cp1252", "replace")

def build_pdf(pages):
    objects = [None]
    def add(value): objects.append(value); return len(objects)-1
    catalog_id = add(b"")
    pages_id = add(b"")
    font_regular = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    font_bold = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
    page_ids=[]
    for number, page in enumerate(pages, 1):
        data=stream_for(page,number,len(pages))
        content_id=add(b"<< /Length "+str(len(data)).encode()+b" >>\nstream\n"+data+b"\nendstream")
        page_id=add(f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] /Resources << /Font << /F1 {font_regular} 0 R /F2 {font_bold} 0 R >> >> /Contents {content_id} 0 R >>".encode())
        page_ids.append(page_id)
    objects[catalog_id]=f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode()
    kids=" ".join(f"{pid} 0 R" for pid in page_ids)
    objects[pages_id]=f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode()
    pdf=bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets=[0]
    for i,obj in enumerate(objects[1:],1):
        offsets.append(len(pdf)); pdf.extend(f"{i} 0 obj\n".encode()); pdf.extend(obj); pdf.extend(b"\nendobj\n")
    xref=len(pdf); pdf.extend(f"xref\n0 {len(objects)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]: pdf.extend(f"{offset:010d} 00000 n \n".encode())
    pdf.extend(f"trailer\n<< /Size {len(objects)} /Root {catalog_id} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    OUTPUT.write_bytes(pdf)

if __name__ == "__main__":
    source=SOURCE.read_text(encoding="utf-8")
    pages=make_pages(parse_blocks(source))
    build_pdf(pages)
    print(f"Created {OUTPUT} ({OUTPUT.stat().st_size} bytes, {len(pages)} pages)")
