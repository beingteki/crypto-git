#!/usr/bin/env python3
"""Rebuild the Word report, result tables, and plots from the recorded runs."""

import argparse
import csv
from hashlib import sha256
from pathlib import Path

from docx import Document
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

from analyse_results import GRAPHS, TABLES, main as analyse

ROOT = Path(__file__).resolve().parent
REPORT = ROOT / "reports" / "CryptoBench_Report.docx"
DISCUSSION_DATA_SHA256 = {
    "run-1": "6b44241384b026c1a982b265f43887e151ece6113d76f19c6ac61ca75401e846",
    "run-2": "ded7ec06cd75b250ab4029592cd965f58c6f29f42bd0a4dc7a5557fb9bdb9525",
}
RESULTS = [
    ("kem", "Key establishment", ("Key generation", "Encapsulate", "Decapsulate")),
    ("signature", "Digital signatures", ("Key generation", "Sign", "Verify")),
    ("aead", "Authenticated encryption", ("Encrypt", "Decrypt")),
]


def table(doc, header_rows, data_rows, widths):
    result = doc.add_table(rows=0, cols=len(widths))
    result.style = "Table Grid"
    result.alignment = WD_TABLE_ALIGNMENT.CENTER
    result.autofit = False
    for column, width in zip(result.columns, widths):
        column.width = Inches(width)
    for index, values in enumerate([*header_rows, *data_rows]):
        row = result.add_row()
        properties = row._tr.get_or_add_trPr()
        properties.append(OxmlElement("w:cantSplit"))
        is_header = index < len(header_rows)
        if is_header:
            properties.append(OxmlElement("w:tblHeader"))
        for col, (cell, value, width) in enumerate(zip(row.cells, values, widths)):
            cell.width = Inches(width)
            cell.text = str(value)
            shade = OxmlElement("w:shd")
            shade.set(qn("w:fill"), "193B63" if is_header else ("F0F5F9" if index % 2 == 0 else "FFFFFF"))
            cell._tc.get_or_add_tcPr().append(shade)
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT if col == 0 or len(widths) == 3 else WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_after = Pt(2)
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.line_spacing = 1
            for run in p.runs:
                run.font.size = Pt(9)
                run.bold = is_header
                if is_header:
                    run.font.color.rgb = RGBColor(255, 255, 255)
    return result


def caption(doc, text, before=False):
    p = doc.add_paragraph(text, style="Caption")
    p.paragraph_format.keep_with_next = before
    return p


def result_page(doc, env, item, number):
    part, title, operations = item
    aead = part == "aead"
    if env == 1:
        doc.add_heading(f"{number + 1}. {title}", level=1)
    else:
        if number == 4:
            doc.add_heading("5. Second environment", level=1)
            doc.add_paragraph(
                "The same benchmark ran on the Kali Linux guest described in Part 1. "
                "Tables 4–6 and Figures 4–6 use the same calculations and plot formats as Environment 1."
            )
        doc.add_heading(title, level=2)
    env_label = f"Environment {env} ({'macOS' if env == 1 else 'Kali Linux VM'})"
    caption(doc, f"Table {number}. {title}, {env_label}. Times in ms.", before=True)
    with (TABLES / f"environment_{env}_{part}.csv").open(newline="", encoding="utf-8") as source:
        reader = csv.reader(source)
        next(reader)
        rows = list(reader)

    labels = ["Algorithm", "Message (B)"] if aead else ["Algorithm"]
    measure_start = len(labels)
    operation_header = [""] * measure_start
    for op in operations:
        operation_header.extend((op, ""))
    widths = [1.85, 1, .97, .97, .97, .97] if aead else [1.55] + [.86] * 6
    result = table(doc, [operation_header, labels + ["Median", "IQR"] * len(operations)], rows, widths)
    for index in range(measure_start, len(widths), 2):
        result.cell(0, index).merge(result.cell(0, index + 1))
    for index in range(measure_start):
        result.cell(0, index).merge(result.cell(1, index))

    image = doc.add_paragraph()
    image.alignment = WD_ALIGN_PARAGRAPH.CENTER
    image.paragraph_format.space_before = Pt(6)
    image.paragraph_format.space_after = Pt(1)
    image.paragraph_format.keep_with_next = True
    image.add_run().add_picture(str(GRAPHS / f"environment_{env}_{part}.png"), width=Inches(4.95 if aead else 6.6))
    description = "Median encryption time by message size" if aead else "Median times by operation (error bars span Q1 to Q3)"
    caption(doc, f"Figure {number}. {description}, {env_label}.")


def setup(doc, student_name, student_id, repository_url):
    doc.add_paragraph("CryptoBench", style="Report Title")
    doc.add_paragraph("Modern Cryptography · Performance benchmark", style="Subtitle")
    doc.add_paragraph(f"Name  {student_name or '[Student Name]'}     Student ID  {student_id or '[Student ID]'}")
    doc.add_paragraph(f"Repository  {repository_url or '[GitHub/GitLab URL]'}")
    doc.add_heading("1. Experimental setup", level=1)
    table(
        doc,
        [["Field", "Environment 1 · MacBook Pro", "Environment 2 · Kali Linux VM"]],
        [
            ["CPU and architecture", "Apple M3 Pro, ARM64", "Intel Core i3-1115G4, x86-64 (host and guest)"],
            ["Cores and memory", "11 physical cores, 11 logical CPUs, 18.0 GiB RAM",
             "Guest: 2 vCPUs and 4096 MB RAM allocated (VBoxManage). Kali sees 3.83 GiB. Host: 2 physical cores, 4 logical CPUs, 19.7 GiB RAM."],
            ["Operating system", "macOS 27.2.1", "Kali Linux, kernel 6.19.14+kali-amd64. Host: ASUS VivoBook X415EA, Windows 11 Home (build 10.0.26300)."],
            ["Hypervisor", "Physical machine", "Oracle VirtualBox 7.2.20r175154"],
            ["Python / pyca/cryptography", "3.14.7 / 50.0.2", "3.14.7 / 50.0.2"],
            ["OpenSSL", "cryptography backend 4.0.3. Python ssl module 3.6.1.", "cryptography backend 4.0.3. Python ssl module 3.6.2."],
        ],
        [1.40, 2.63, 2.78],
    )
    doc.add_heading("Benchmark procedure", level=2)
    doc.add_paragraph(
        "The same single-threaded Python script measured elapsed time on both environments with "
        "time.perf_counter_ns(). Each operation used 101 individually timed calls, with 21 calls for "
        "RSA key generation. The CSVs retain run 0, the warm-up. Medians and interquartile ranges "
        "(IQR = Q3 − Q1) use the remaining 100 or 20 calls and the default exclusive quartiles "
        "from statistics.quantiles with n=4. Tables show milliseconds to three significant figures where available."
    )
    doc.add_paragraph(
        "Each algorithm reused one key pair for its non-keygen operations. RSA-OAEP encapsulation timed "
        "generation and encryption of a random 32-byte secret. Decapsulation reused a ciphertext made "
        "before timing. ECDH, X25519 and ML-KEM also used one fixed ciphertext generated by their "
        "respective encapsulation routines. ECDH and X25519 timed ephemeral key generation, exchange "
        "and encoding during encapsulation, and parsing plus exchange during decapsulation. Fixed "
        "padding, signature configuration and receiver public keys were prepared outside timing. "
        "Signatures used a module-level random 1 KiB message and a fixed signature per algorithm "
        "for verification. Each AEAD encryption nonce was generated before timing, and timed "
        "decryption reused a prepared nonce and ciphertext."
    )
    doc.add_paragraph(
        "The recorded runs are stored in results/run-1/raw.csv and results/run-2/raw.csv. "
        "The command python build_report.py regenerates all six tables and plots and this Word report "
        "from those files. Each raw file contains 8,063 rows across 83 operation groups."
    )


def discussion(doc):
    doc.add_heading("6. Discussion of results", level=1)
    doc.add_heading("6.1 Fastest and slowest by operation", level=2)
    caption(
        doc,
        "Table 7. Fastest and slowest medians in each environment, from Tables 1–6. Times in ms.",
        before=True,
    )
    table(
        doc,
        [["Operation", "Environment 1 · fastest / slowest", "Environment 2 · fastest / slowest"]],
        [
            ["Key establishment · keygen", "ECDH-P-256 0.00817 / RSA-OAEP-7680 2,770", "ECDH-P-256 0.0116 / RSA-OAEP-7680 6,530"],
            ["Encapsulate", "ML-KEM-768 0.0112 / ECDH-P-521 0.257", "ML-KEM-768 0.0202 / ECDH-P-384 0.440"],
            ["Decapsulate", "ML-KEM-768 0.0167 / RSA-OAEP-7680 20.3", "ML-KEM-768 0.0309 / RSA-OAEP-7680 34.5"],
            ["Signature · keygen", "ECDSA-P-256 0.00808 / RSA-PSS-7680 2,910", "ECDSA-P-256 0.0117 / RSA-PSS-7680 4,600"],
            ["Sign", "ECDSA-P-256 0.0157 / RSA-PSS-7680 20.3", "ECDSA-P-256 0.0225 / RSA-PSS-7680 34.6"],
            ["Verify", "RSA-PSS-3072 0.0295 / ECDSA-P-521 0.269", "RSA-PSS-3072 0.0415 / ECDSA-P-521 0.463"],
            ["Encrypt · 1 MiB", "AES-128-GCM 0.105 / AES-256-GCM-SIV 1.26", "AES-128-GCM 0.155 / AES-256-GCM-SIV 2.13"],
            ["Decrypt · 1 MiB", "AES-128-GCM 0.106 / AES-256-GCM-SIV 1.26", "AES-128-GCM 0.178 / AES-256-GCM-SIV 2.05"],
        ],
        [1.42, 2.65, 2.65],
    )
    doc.add_heading("Key establishment", level=3)
    doc.add_paragraph(
        "ECDH-P-256 draws a private scalar and derives its public point. RSA-OAEP-7680 must search for "
        "large primes, making its key generation slower. The small public exponent keeps macOS "
        "RSA-OAEP-3072 encapsulation short (0.0277 ms), while private-key modular exponentiation raises "
        "decapsulation to 1.25 ms. ECDH encapsulation includes ephemeral key generation, scalar "
        "multiplication and public-point encoding. The largest curves had the highest encapsulation "
        "medians within ECDH. ML-KEM-768 had the lowest encapsulation and decapsulation medians "
        "using efficient polynomial arithmetic [1, 3, 5]."
    )
    doc.add_heading("Digital signatures", level=3)
    doc.add_paragraph(
        "RSA-PSS-7680 had the slowest key generation and signing. These operations search for large "
        "primes and perform private-key exponentiation, respectively. ECDSA-P-256 draws a scalar for "
        "key generation and uses a smaller curve for signing. ECDSA verification combines two scalar "
        "multiplications, and P-521 had the slowest verification. RSA-PSS-3072 verified fastest in both "
        "runs using its small public exponent [1, 2]."
    )
    doc.add_heading("Authenticated encryption", level=3)
    doc.add_paragraph(
        "AES-256-GCM-SIV was slowest for both operations at every size. On macOS, AES-128-GCM and "
        "AES-256-GCM tied for fastest encryption at 64 B and 1 KiB and for fastest decryption at "
        "64 B. AES-128-GCM led the remaining Mac cases. In Kali, AES-128-GCM led 64 B and 1 MiB "
        "encryption and 1 MiB decryption. AES-256-GCM led the remaining Kali cases (Tables 3 and 6). "
        "GCM can parallelise counter-mode AES and GHASH. GCM-SIV computes a synthetic IV over the "
        "plaintext before encrypting it in a second pass. During decryption it recomputes the tag "
        "from recovered plaintext [7, 9]."
    )

    scaling = doc.add_heading("6.2 Growth with security level and message length", level=2)
    scaling.paragraph_format.page_break_before = True
    doc.add_paragraph(
        "RSA and curves. Mac RSA-OAEP decapsulation rises from 1.25 to 20.3 ms as the modulus "
        "grows from 3,072 to 7,680 bits (16.3× using unrounded medians). The larger modulus increases "
        "the cost of modular arithmetic. RSA-OAEP-7680 keygen has a 2,310 ms IQR around a 2,770 ms "
        "median because prime search can test different numbers of candidates. Mac ECDH keygen rose "
        "from 0.00817 to 0.0604 to 0.0739 ms across P-256, P-384 and P-521. ECDSA verification across "
        "those curves rose from 0.0407 to 0.193 to 0.269 ms (Tables 1 and 2). Larger fields require "
        "more arithmetic, but the implementation affects the scaling. Kali ECDH-P-521 decapsulation "
        "was slightly quicker than P-384 (0.296 vs 0.301 ms), with IQRs of 0.0107 and 0.00926 ms "
        "(Table 4) [1–3]."
    )
    doc.add_paragraph(
        "Lattice parameters and AES key length. On macOS, ML-KEM encapsulation rose from 0.0112 "
        "to 0.0157 ms from parameter set 768 to 1024, which uses larger module dimensions. "
        "ML-DSA signing increased from 0.247 to 0.388 to 0.440 ms across 44, 65 and 87 as the "
        "polynomial workload grew (Tables 1 and 2). AES-256 uses 14 rounds versus 10 for AES-128. "
        "At 1 MiB, AES-256-GCM encryption took 0.123 vs 0.105 ms on macOS and 0.182 vs 0.155 ms "
        "in Kali. At shorter Kali lengths, AES-256-GCM sometimes led, so rounds alone do not "
        "predict these observed latencies (Tables 3 and 6) [5–8]."
    )
    doc.add_paragraph(
        "Message length. On macOS, AES-128-GCM encryption rose from 0.000417 ms at 64 B to "
        "0.000542 ms at 1 KiB, 0.00217 ms at 16 KiB and 0.105 ms at 1 MiB (Table 3, Figure 3). "
        "Fixed call and per-message costs weigh most at short lengths. More block operations "
        "and authentication work drive the steep rise at larger sizes. Kali AES-256-GCM shows a "
        "small dip from 0.000984 to 0.000878 ms at the first two sizes. That decrease is "
        "smaller than the 64 B IQR of 0.000432 ms. The 1 MiB median reaches 0.182 ms "
        "(Table 6, Figure 6) [6, 7]."
    )

    doc.add_heading("6.3 Classical and post-quantum algorithms", level=2)
    doc.add_paragraph(
        "Key establishment. In the brief's 192-bit grouping, Mac ML-KEM-768 encapsulated in "
        "0.0112 ms versus 0.221 ms for ECDH-P-384 and 0.144 ms for RSA-OAEP-7680 (Table 1). "
        "ML-KEM uses a number-theoretic transform for polynomial multiplication. ECDH additionally "
        "generates and serializes an ephemeral key, while RSA-OAEP encrypts a generated secret "
        "with modular arithmetic. X25519 uses a different security grouping and took 0.0480 ms. "
        "Its 32-byte ephemeral public value is smaller than ML-KEM-768's 1,088-byte ciphertext [1, 3–5]."
    )
    doc.add_paragraph(
        "Signatures. In the brief's 192-bit grouping, Mac ML-DSA-65 signing (0.388 ms) fell "
        "between ECDSA-P-384 (0.0921 ms) and RSA-PSS-7680 (20.3 ms). ML-DSA-44 signed in 0.247 ms "
        "versus Ed25519's 0.0249 ms, but verified in 0.0557 ms versus Ed25519's 0.0685 ms. Mac "
        "ECDSA-P-256 and RSA-PSS-3072 verified faster at 0.0407 and 0.0295 ms. ML-DSA candidate "
        "rejection can vary signing work. Its signing IQR was 0.232 ms versus 0.00376 ms for "
        "verification. ML-DSA-44 signatures occupy 2,420 B, compared with 64 B for Ed25519 and "
        "384 B for RSA-PSS-3072 (Table 2) [1, 2, 8, 10]."
    )

    comparison = doc.add_heading("6.4 What changed in the second environment", level=2)
    comparison.paragraph_format.page_break_before = True
    doc.add_paragraph(
        "Kali medians were higher in 81 of 83 matched groups. The exceptions were 1 MiB "
        "ChaCha20-Poly1305 encryption (0.508 to 0.457 ms) and decryption (0.514 to 0.466 ms), "
        "with Kali/Mac ratios of 0.900 and 0.907. At 1 MiB, the AES-128-GCM encryption lead over "
        "ChaCha20-Poly1305 narrowed from 4.84× on macOS to 2.95× in Kali. AES-256-GCM encryption "
        "took 1.48× as long in Kali, and its IQR rose from 0.000292 to 0.0168 ms (Tables 3 and 6). "
        "GCM runs AES and GHASH, whereas ChaCha20 uses addition, rotation and XOR and Poly1305 "
        "provides authentication. Different optimized paths could change their relative costs [7, 11]."
    )
    doc.add_paragraph(
        "ML-KEM-768 remained the fastest decapsulator, but its lead over X25519 narrowed. "
        "The Kali/Mac ratios were 1.85 for ML-KEM-768 and 1.29 for X25519. In Kali their medians "
        "were 0.0309 and 0.0316 ms, a 0.000631 ms gap using unrounded medians. The two routines "
        "exercise different arithmetic: lattice polynomials versus X25519 scalar multiplication "
        "plus parsing the ephemeral public key. The slowest ECDH encapsulation moved from "
        "P-521 to P-384 in Kali, where the medians were 0.431 and 0.440 ms. That within-family "
        "gap is smaller than either IQR, so the rank describes these runs (Tables 1 and 4) [3–5]."
    )
    doc.add_paragraph(
        "RSA-OAEP-7680 key generation rose from 2,770 to 6,530 ms (2.36×), and its IQR rose "
        "from 2,310 to 3,890 ms. Prime search helps explain why the spread is large on both hosts "
        "(Tables 1 and 4). All ratios use unrounded medians. Each environment contributes one "
        "session. CPU, OS, scheduling and virtualization vary together, which limits causal "
        "attribution. An IQR describes variation within the session. Four Mac AEAD groups have "
        "zero IQR because their recorded Q1 and Q3 are equal (Table 3)."
    )


def references(doc):
    doc.add_heading("References", level=1)
    sources = [
        "RFC 8017, PKCS #1 v2.2. https://www.rfc-editor.org/rfc/rfc8017",
        "NIST FIPS 186-5, Digital Signature Standard. https://csrc.nist.gov/pubs/fips/186-5/final",
        "NIST SP 800-56A Rev. 3, Pair-Wise Key Establishment Using Discrete Logarithm Cryptography. https://csrc.nist.gov/pubs/sp/800/56/a/r3/final",
        "RFC 7748, Elliptic Curves for Security. https://www.rfc-editor.org/rfc/rfc7748",
        "NIST FIPS 203, ML-KEM. https://csrc.nist.gov/pubs/fips/203/final",
        "NIST FIPS 197, Advanced Encryption Standard. https://csrc.nist.gov/pubs/fips/197/final",
        "NIST SP 800-38D, GCM and GMAC. https://csrc.nist.gov/pubs/sp/800/38/d/final",
        "NIST FIPS 204, ML-DSA. https://csrc.nist.gov/pubs/fips/204/final",
        "RFC 8452, AES-GCM-SIV. https://www.rfc-editor.org/rfc/rfc8452",
        "RFC 8032, Edwards-Curve Digital Signature Algorithm. https://www.rfc-editor.org/rfc/rfc8032",
        "RFC 8439, ChaCha20 and Poly1305 for IETF Protocols. https://www.rfc-editor.org/rfc/rfc8439",
    ]
    for index, source in enumerate(sources, start=1):
        p = doc.add_paragraph(f"[{index}] {source}")
        p.paragraph_format.space_after = Pt(3)
    doc.add_heading("AI assistance declaration", level=2)
    doc.add_paragraph(
        "OpenAI Codex was used to interpret the feedback and rubric, revise the Python report generator "
        "and benchmark timing code, recalculate statistics and check the outputs against the recorded CSVs, "
        "draft and edit the discussion, and format and verify the Word and PDF files. The earlier rework "
        "also disclosed AI assistance with code review, analysis-script development, summarisation, "
        "technical explanation and formatting."
    )


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--student-name", default="", help="Name to place on the cover and in Word metadata")
    args.add_argument("--student-id", default="", help="Student ID to place on the cover")
    args.add_argument("--repository-url", default="", help="Verified submission repository URL")
    identity = args.parse_args()

    for run, expected_hash in DISCUSSION_DATA_SHA256.items():
        raw_path = ROOT / "results" / run / "raw.csv"
        if sha256(raw_path.read_bytes()).hexdigest() != expected_hash:
            raise SystemExit(
                f"The written discussion covers the packaged data. For new captures use "
                f"analyse_results.py and revise the discussion before rebuilding ({raw_path})."
            )
    analyse()
    doc = Document()
    section = doc.sections[0]
    section.page_width = Inches(8.27)
    section.page_height = Inches(11.69)
    section.top_margin = Inches(.64)
    section.bottom_margin = Inches(.60)
    section.left_margin = section.right_margin = Inches(.70)
    section.footer_distance = Inches(.30)

    doc.styles.add_style("Report Title", WD_STYLE_TYPE.PARAGRAPH)
    for name, size, color in [
        ("Normal", 10.5, "263344"), ("Report Title", 30, "193B63"), ("Subtitle", 12, "516479"),
        ("Heading 1", 17, "193B63"), ("Heading 2", 12, "286183"),
        ("Heading 3", 11, "286183"), ("Caption", 9, "516479"),
    ]:
        style = doc.styles[name]
        style.font.name = "Arial"
        style.font.size = Pt(size)
        style.font.color.rgb = RGBColor.from_string(color)
        style.paragraph_format.space_after = Pt(5)

    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.add_run("CryptoBench  ·  ").font.size = Pt(9)
    field = OxmlElement("w:fldSimple")
    field.set(qn("w:instr"), "PAGE")
    footer._p.append(field)

    setup(doc, identity.student_name, identity.student_id, identity.repository_url)
    for env in (1, 2):
        for i, item in enumerate(RESULTS, start=1):
            doc.add_page_break()
            result_page(doc, env, item, (env - 1) * 3 + i)
    doc.add_page_break()
    discussion(doc)
    references(doc)

    doc.core_properties.title = "CryptoBench"
    doc.core_properties.subject = "Modern Cryptography performance benchmark"
    doc.core_properties.author = identity.student_name
    doc.core_properties.last_modified_by = ""
    REPORT.parent.mkdir(exist_ok=True)
    doc.save(REPORT)
    print(f"Word report: {REPORT}")


if __name__ == "__main__":
    main()
