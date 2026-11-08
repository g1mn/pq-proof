# Diagrams

Made with archify 3.2 (JSON in, checked standalone HTML out) from the `*.archify.json` sources here. Each diagram passed archify's `finalize` gates (schema, layout, delivery check and a real-browser check).

| Diagram | Interactive | Images | Source |
|---|---|---|---|
| Architecture on Vultr | [architecture.html](architecture.html) | [PNG](architecture.png) · [dark SVG](architecture.dark.svg) · [light SVG](architecture.light.svg) | [architecture.archify.json](architecture.archify.json) |
| One run, step by step | [sequence.html](sequence.html) | [PNG](sequence.png) · [dark SVG](sequence.dark.svg) · [light SVG](sequence.light.svg) | [sequence.archify.json](sequence.archify.json) |
| Containment data flow | [containment.html](containment.html) | [PNG](containment.png) · [dark SVG](containment.dark.svg) · [light SVG](containment.light.svg) | [containment.archify.json](containment.archify.json) |

The HTML files are self-contained: download one and open it in a browser for live motion, focus, search and PNG/SVG/WebM export. GitHub shows HTML as source, not as a page.

The diagrams describe the code in this repository (see the README sections they sit in). The run-specific values in the containment diagram (`203.0.113.7`, `CANARY-0001`, 253 bytes) come from the receipt of run `e2e-glm-7`.
