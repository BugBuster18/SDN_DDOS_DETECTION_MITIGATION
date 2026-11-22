"""Build the Deep Review revision deliverables from revision_log.json.

Outputs (paper/revisions/out/):
  Revision_Report.docx / .html          per round: upload details, new experiments, comment -> change table
  DeepReview_Comments_AllRounds.docx / .html   verbatim Deep Review output of every round
The .html files are printed to PDF with headless Chrome (render_pdfs.ps1).
"""
import html
import json
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.shared import Pt, RGBColor

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
OUT.mkdir(exist_ok=True)
log = json.loads((HERE / "revision_log.json").read_text(encoding="utf-8"))
CSS = """<style>
@page{size:A4;margin:14mm}body{font-family:'Segoe UI',Arial,sans-serif;font-size:9.5pt;color:#111;max-width:820px;margin:auto}
h1{font-size:17pt;margin:0 0 4px}h2{font-size:13pt;border-bottom:2px solid #111;padding-bottom:2px;margin-top:20px;page-break-after:avoid}
h3{font-size:11pt;margin:12px 0 4px}table{border-collapse:collapse;width:100%;margin:6px 0 10px;font-size:8.6pt}
th,td{border:1px solid #c9c7c1;padding:3px 5px;vertical-align:top;text-align:left}th{background:#f1f0ec}tr{page-break-inside:avoid}
.sub{color:#52514e}.st{font-weight:600}td{overflow-wrap:anywhere}pre{white-space:pre-wrap;font-family:Consolas,monospace;font-size:8.2pt;
background:#f7f6f3;border:1px solid #e1dfda;padding:8px}</style>"""


def esc(s):
    return html.escape(str(s))


# ------------------------------------------------------------------ Revision report
doc = Document()
st = doc.styles["Normal"]
st.font.name = "Calibri"
st.font.size = Pt(10)
doc.add_heading("Revision Report: Google Deep Review", 0)
doc.add_paragraph(log["title"])
doc.add_paragraph(f'{log["group"]}: {log["authors"]}')
doc.add_paragraph(f'Review tool: {log["tool"]}')
doc.add_paragraph(
    "For every review round this report lists the uploaded manuscript, the new experiments that were needed, and each "
    "Deep Review comment with the modification made and where it appears in the revised manuscript. The complete, "
    "unedited Deep Review output of every round is provided separately in DeepReview_Comments_AllRounds.")
h = [f"<!doctype html><html><head><meta charset='utf-8'><title>Revision Report</title>{CSS}</head><body>",
     "<h1>Revision Report: Google Deep Review</h1>",
     f"<div class='sub'>{esc(log['title'])}<br>{esc(log['group'])}: {esc(log['authors'])}<br>Review tool: {esc(log['tool'])}</div>",
     "<p>For every review round this report lists the uploaded manuscript, the new experiments that were needed, and each "
     "Deep Review comment with the modification made and where it appears in the revised manuscript. The complete, "
     "unedited Deep Review output of every round is provided separately in <i>DeepReview_Comments_AllRounds</i>.</p>"]

# summary table of rounds
doc.add_heading("Summary of rounds", 1)
t = doc.add_table(rows=1, cols=5)
t.style = "Light Grid Accent 1"
for c, txt in zip(t.rows[0].cells, ["Round", "Manuscript reviewed", "Review ID", "Comments", "Revised manuscript"]):
    c.text = txt
h.append("<h2>Summary of rounds</h2><table><tr><th>Round</th><th>Manuscript reviewed</th><th>Review ID</th><th>Comments</th><th>Revised manuscript</th></tr>")
for r in log["rounds"]:
    row = [str(r["round"]), f'{r["uploaded_file"]} ({r["uploaded_on"]})', r["review_id"], str(len(r["items"])), r.get("revised_file", "")]
    cells = t.add_row().cells
    for c, txt in zip(cells, row):
        c.text = txt
    h.append("<tr>" + "".join(f"<td>{esc(x)}</td>" for x in row) + "</tr>")
h.append("</table>")

for r in log["rounds"]:
    doc.add_heading(f'Round {r["round"]}: review of {r["uploaded_file"]}', 1)
    doc.add_paragraph(f'Uploaded on {r["uploaded_on"]}; Deep Review document ID {r["review_id"]}.')
    doc.add_paragraph(f'Context given to Deep Review: "{r["custom_context"]}"')
    if r.get("summary"):
        doc.add_paragraph(r["summary"])
    h.append(f'<h2>Round {r["round"]}: review of {esc(r["uploaded_file"])}</h2>'
             f'<p>Uploaded on {esc(r["uploaded_on"])}; Deep Review document ID {esc(r["review_id"])}.<br>'
             f'Context given to Deep Review: <i>"{esc(r["custom_context"])}"</i></p>')
    if r.get("summary"):
        h.append(f"<p>{esc(r['summary'])}</p>")
    if r.get("new_experiments"):
        doc.add_heading("New experiments and analyses in this revision", 2)
        h.append("<h3>New experiments and analyses in this revision</h3><ul>")
        for e in r["new_experiments"]:
            doc.add_paragraph(e, style="List Bullet")
            h.append(f"<li>{esc(e)}</li>")
        h.append("</ul>")
    doc.add_heading("Comments and modifications", 2)
    tb = doc.add_table(rows=1, cols=5)
    tb.style = "Light Grid Accent 1"
    tb.alignment = WD_TABLE_ALIGNMENT.CENTER
    for c, txt in zip(tb.rows[0].cells, ["#", "Deep Review comment", "Modification made", "Where", "Status"]):
        c.text = txt
    h.append("<h3>Comments and modifications</h3><table style='table-layout:fixed'><colgroup><col style='width:5%'>"
             "<col style='width:30%'><col style='width:42%'><col style='width:11%'><col style='width:12%'></colgroup>"
             "<tr><th>#</th><th>Deep Review comment (type)</th>"
             "<th>Modification made</th><th>Where</th><th>Status</th></tr>")
    for it in r["items"]:
        cells = tb.add_row().cells
        vals = [it["id"], f'[{it["type"]}] {it["comment"]}', it["response"], it["where"], it["status"]]
        for c, txt in zip(cells, vals):
            c.text = txt
            for p in c.paragraphs:
                for run in p.runs:
                    run.font.size = Pt(8.5)
        h.append(f"<tr><td>{esc(it['id'])}</td><td><b>{esc(it['type'])}</b><br>{esc(it['comment'])}</td><td>{esc(it['response'])}</td>"
                 f"<td>{esc(it['where'])}</td><td class='st'>{esc(it['status'])}</td></tr>")
    h.append("</table>")
    counts = {}
    for it in r["items"]:
        k = it["status"].split(" (")[0]
        counts[k] = counts.get(k, 0) + 1
    line = "Status count: " + ", ".join(f"{v} {k.lower()}" for k, v in counts.items()) + "."
    doc.add_paragraph(line)
    h.append(f"<p><b>{esc(line)}</b></p>")
doc.save(OUT / "Revision_Report.docx")
h.append("</body></html>")
(OUT / "Revision_Report.html").write_text("\n".join(h), encoding="utf-8")

# ------------------------------------------------------------------ verbatim comments
doc = Document()
doc.styles["Normal"].font.name = "Calibri"
doc.styles["Normal"].font.size = Pt(9)
doc.add_heading("Google Deep Review: complete comments, all rounds", 0)
doc.add_paragraph(log["title"])
doc.add_paragraph("Unedited output of Google Deep Review (copied with its 'Copy Report' button). Mathematics appears in "
                  "the LaTeX notation that Deep Review exports.")
h = [f"<!doctype html><html><head><meta charset='utf-8'><title>Deep Review Comments</title>{CSS}</head><body>",
     "<h1>Google Deep Review: complete comments, all rounds</h1>",
     f"<div class='sub'>{esc(log['title'])}<br>Unedited output of Google Deep Review (copied with its 'Copy Report' button). "
     "Mathematics appears in the LaTeX notation that Deep Review exports.</div>"]
for r in log["rounds"]:
    text = (HERE / r["verbatim_file"]).read_text(encoding="utf-8")
    doc.add_heading(f'Round {r["round"]}: {r["uploaded_file"]} (review ID {r["review_id"]}, {r["uploaded_on"]})', 1)
    for line in text.splitlines():
        p = doc.add_paragraph(line)
        for run in p.runs:
            run.font.size = Pt(8.5)
            if line.startswith("#"):
                run.bold = True
                run.font.color.rgb = RGBColor(0x1C, 0x5C, 0xAB)
    h.append(f'<h2>Round {r["round"]}: {esc(r["uploaded_file"])}</h2><div class="sub">Review ID {esc(r["review_id"])}, '
             f'{esc(r["uploaded_on"])}</div><pre>{esc(text)}</pre>')
doc.save(OUT / "DeepReview_Comments_AllRounds.docx")
h.append("</body></html>")
(OUT / "DeepReview_Comments_AllRounds.html").write_text("\n".join(h), encoding="utf-8")
print("built:", sorted(p.name for p in OUT.iterdir()))
