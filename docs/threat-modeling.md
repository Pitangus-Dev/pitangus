English · [Español](es/modelado-de-amenazas.md)

# Threat modeling

Scanners find flaws in what's already written. **Threat modeling** looks at the design: you draw the system (its
components, the data flowing between them and the trust boundaries they cross) and ask what could go wrong at each
point. **Threats** (`#/threats`) lets you draw that model, apply a method such as STRIDE, and check each threat
against what your scans found. A threat is a scenario to review, not a confirmed flaw. Terms are explained in the
[glossary](glossary.md).

## Prerequisites

- Pitangus running. A model needs no repositories, but linking its components to scanned repositories or verified
  domains is what brings in evidence ([Scan your code](scanning-code.md)).
- To get component suggestions from a GitHub repository: the GitHub App installed on it, with `contents: read`
  ([Connecting GitHub](github-app.md)).

## Create a model

1. Open **Threats** and click **New model**.
2. Give the project a name (for example "Payments" or "Customer portal") and choose an **Approach** (below). You can
   change it later without losing the diagram.
3. Optionally, under **Start from repositories (optional)**, pick one or more repositories and click
   **Create and propose components**: Pitangus suggests components and flows from their manifests (see
   [Suggestions from repositories](#suggestions-from-repositories)).
4. Draw or adjust the system in **Diagram**, then click **Save and recalculate**.

Each model is a project: associate the **Project repositories** whenever you want, one or several (microservices,
microfrontends). A component linked to a repository adds it to the list automatically.

### Approaches

| Approach | What for | What Pitangus does |
| --- | --- | --- |
| STRIDE | Security threats to components and flows (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege) | Built-in rules on the diagram (`TM-*`) |
| LINDDUN | Threats to people's privacy | Built-in rules on the elements that hold personal data (`PV-*`) |
| PASTA | Business risk in seven stages | Stages with notes; stages 3, 4 and 5 are fed by the diagram, STRIDE and the scans |
| Attack trees | Paths toward an attacker's goal | AND/OR tree editor with difficulty, element and mitigation; works out which paths are still open |
| MITRE ATT&CK | Real attackers' techniques | A selection of techniques (web, API, containers, cloud) to map onto components, with suggestions and a link to attack.mitre.org |
| Custom | Your team's method | The diagram plus whichever tools you turn on: STRIDE or LINDDUN rules, your own threats, PASTA stages, attack trees, ATT&CK and the element table |

In any approach you can **add your own threats**: title, scenario, category, element, severity, likelihood, impact,
owner and mitigation. Each approach has a **Guide** (what each letter means, the stages, how to build a tree) that
opens next to your work and remembers whether you left it open; STRIDE and LINDDUN categories show their guiding
question on hover.

**The built-in rules are visible** (STRIDE `TM-S01`…`TM-E02` in `pitangus/modules/threats/model.py`, LINDDUN `PV-*`
in `pitangus/modules/threats/methods.py`). Each threat says what triggers it on that element, its severity, its
mitigations and its CWEs. The severity starts from the rule's base, goes one level up if the element is exposed to
the internet and carries credentials or payments, and one level down if it's internal and not very sensitive.

## Draw the system

In **Diagram**:

- **Components**: add them from the canvas toolbar and drag them. Types: actor, web app, API, service, function,
  database, cache, queue, storage, third party and identity provider. **Other type (you name it)** creates a custom
  type with any name and a **base role**, which decides which automatic rules apply to it.
- **Flows**: connect two components by dragging between their connection points. A flow says what it carries, its
  protocol, its data, and whether it's authenticated and encrypted in transit.
- **Trust boundaries** are boxes you can move (their components move with them) and resize. A component belongs to
  the boundary that contains its center.
- **Select an element** to edit it in the side panel: name, type, technology, description, the data it stores or
  handles, and properties such as internet-facing or authenticates. There you also link a component to a repository
  or a domain, and set its **Folder in the repository** (see [Evidence](#evidence-not-confirmation)).
- **Resize** components and boundaries by dragging an edge or a corner (the handles appear on hover); hold **Shift**
  to keep the aspect ratio.
- **Tidy up** arranges everything in layers (actors, then applications, then APIs and services, then data and third
  parties), each boundary as a block that contains its components.
- Flow labels are placed where they don't overlap components or other labels; long labels are shortened and shown in
  full when you select or hover the flow.

Positions are saved with the model and used by the exports. **Table** is there for editing many components, flows and
boundaries at once. If the server is updated while you work, open tabs show **Reload**: save first.

## Suggestions from repositories

From each repository in the project (when you create it or later), Pitangus suggests components and flows and
**adds them to the diagram without duplicating** what's there, respecting what your team drew: new items go into
their boundary or to the right.

- Up to 10 repositories at a time. Repositories from the GitHub App are read on the spot, scanned or not; a
  repository from the server's workspace is proposed from its latest scan.
- Only manifests are read, through GitHub's API (repository tree and files; the repository isn't downloaded): `package.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `Dockerfile` and
  compose files, up to 40 files, leaving out `node_modules`, fixtures and tests.
- FastAPI, Next.js, Express or axum become processes; psycopg, Prisma, Mongoose or sqlx become databases (an ORM is
  merged with its engine); Stripe, Twilio, S3, next-auth or an LLM SDK become third parties or identity providers.
- **Each suggested component cites the dependency and the file it came from** and is marked as proposed from the
  repository, so the team can correct it.
- Only names are kept, never versions or configuration values.

An unscanned repository is modeled the same way, but its threats have no evidence until it's scanned.

## Evidence, not confirmation

When a component is linked to a repository and that code has open findings with one of a threat's CWEs, the threat
is marked **Evidenced** and links to those findings (**Evidence from scans**). It's a signal to review, not proof that
the scenario is exploitable.

- In a monorepo, set the component's **Folder in the repository** (for example `frontend/`) so only findings from
  its own code count. Without a folder, the whole repository counts, and the threat says so.
- Findings in excluded paths, and findings dismissed in triage, don't count.
- Dependency advisories are evidence of "vulnerable dependencies", not of injection in your own code.

## Decisions

Each threat can be closed with a decision: **Mitigated** (say which control mitigates it and where it can be
verified), **Accepted** (why, and until when) or **Not applicable** (why it doesn't apply to this system). Each
decision keeps its reason, author and date, and can be reopened. If open findings point to the threat, the dialog
says so before you decide.

## Import and export a model as JSON

The model has a portable JSON format you can version, edit by hand or ask an AI assistant to write.

**Import.** In the list, **Import JSON** opens a wizard with a complete example for each approach, an editor to
paste or change the JSON, file upload (600 KB at most), download and copy of the example, and a prompt to copy for an
AI assistant. **Validate JSON** checks it without creating anything; **Import model** is enabled only once the current
text validates.

**Export.** In the editor, **Export → Model JSON (re-importable)** downloads `model.json`: the full diagram (positions,
components, flows and boundaries), the approach, the custom modules, the threats your team wrote, PASTA stages, attack
trees and ATT&CK techniques.

The importer takes both the envelope the panel downloads (`{"format": "pitangus-threat-model", "version": 1,
"model": {…}}`) and a bare model object. A minimal example:

```json
{
  "name": "Customer portal",
  "methodology": "custom",
  "custom_modules": ["stride", "trees", "manual"],
  "repository_refs": ["team/portal"],
  "components": [
    {"id": "customer", "name": "Customer", "kind": "actor"},
    {"id": "api", "name": "API", "kind": "api", "asset_ref": "team/portal", "data": ["pii"]}
  ],
  "flows": [{"id": "login", "source": "customer", "target": "api", "protocol": "https", "authenticated": false}],
  "boundaries": [{"id": "server", "name": "Server", "components": ["api"]}]
}
```

Rules worth knowing:

- **References are pending, never automatic links.** Repositories and domains in the file are kept as
  `repository_refs` and `asset_ref`. They don't need to exist when you import; link them later in the editor.
- **Layout is optional.** `position` (components), `size` (resized components) and `box` (boundaries) can be left
  out: the editor lays everything out. If the positions don't fit their boundaries (a box smaller than its
  components, or two boxes overlapping), the model is laid out again on import and the preview warns you.
- **Sections must match the approach.** The diagram is shared by every approach. STRIDE and LINDDUN accept your own
  threats; PASTA accepts its stages and trees; Attack trees accepts trees; ATT&CK accepts techniques. **Custom**
  accepts any combination, but each section needs its module in `custom_modules` (`stride`, `linddun`, `manual`,
  `pasta`, `trees`, `attack`, `elements`). An incompatible file is rejected with a message saying which section
  doesn't belong and suggesting another approach or Custom.
- When exporting a fixed approach, only its sections are included; data left over from another approach after
  switching doesn't leak into the file.
- Instance IDs, decisions and scan findings aren't part of the portable format.

## Other exports

From **Export** in the editor:

| Export | What it is |
| --- | --- |
| **PDF report** and **Markdown report** | For the development team: what to handle first, the diagram, the threats your team wrote, those with evidence in the scans, and the rule-based threats grouped by pattern, with the details in annexes. The model's threats aren't presented as confirmed flaws. |
| **SVG diagram** | The diagram on its own (`diagram.svg`); pending changes are saved before downloading. |
| **OWASP Threat Dragon** | Threat Dragon v2 JSON. Importing it into Threat Dragon hasn't been tested. |
| **pytm (Python)** | An OWASP pytm script (`tm.py`), for teams that keep their model as code. |

Downloads go through the authenticated API and show the actual error if they fail.

## Common errors

| What you see | Why | What to do |
| --- | --- | --- |
| "This isn't valid JSON" | A comma, quote or brace is wrong | Fix the syntax; validate again. |
| The import says a section doesn't belong | The section isn't allowed for that approach | Change `methodology`, or use `custom` and add the module to `custom_modules`. |
| "The file is over the 600 KB limit" | The model is too large | Split it into several models. |
| No components are proposed from a repository | Its manifests aren't among the supported ones, or the App can't read it | Check the App's access; add components by hand. |
| A threat shows no evidence | The component isn't linked to a scanned repository, or the folder excludes the findings | Link the repository, scan it, and check the component's folder. |

## Next steps

- [Scan your code and dependencies](scanning-code.md): the evidence behind each threat.
- [Findings, triage and remediation](findings.md).
- [Compliance evidence](compliance.md).
- [Glossary](glossary.md).
