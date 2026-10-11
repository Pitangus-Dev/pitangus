English · [Español](es/cumplimiento.md)

# Compliance evidence: SBOM, VEX, audit reports and CRA

Auditors, customers and regulations increasingly ask the same questions: what's inside your software, which known
vulnerabilities affect it, what you decided about each one and how fast you fix them. **Compliance** (`#/compliance`)
turns your scans and your triage into the files that answer them: an **SBOM** (software bill of materials, the list
of components), a **VEX** (vulnerability exploitability exchange, your statement of whether each vulnerability
affects you), technical reports and audit evidence mapped to a framework. For manufacturers selling in the EU, it
adds a kit for the reporting deadlines of the Cyber Resilience Act (**CRA**). Terms are explained in the
[glossary](glossary.md).

> [!NOTE]
> Everything here is **evidence, not certification**. The mapping to each control is indicative, and an audit
> report is technical input for an auditor, not an audit opinion, a certification or an attestation. Review and sign
> it before you hand it over. A Pitangus report doesn't replace a penetration test that SOC 2 or ISO 27001 may
> require.

## Prerequisites

- At least one **completed full scan** of a repository or an image. The SBOM and the consolidated files are built
  from the latest full scan; a run where an engine didn't run doesn't count. See
  [Scan your code](scanning-code.md) and [Scan container images](scanning-images.md).
- Triage done where it matters: the VEX and the exceptions in the audit evidence come from it
  ([Findings, triage and remediation](findings.md)).
- For the CRA kit: an administrator.

## Download evidence

1. Open **Compliance**.
2. Under **Evidence**, choose the scope: one **Repository or image**, **An organization**, **Choose several** or
   **All** (the same picker as in Findings). With a repository come the images built from it, unless you turn that
   off.
3. Pick the **Framework for audit evidence** (see [Frameworks](#frameworks)).
4. Download what you need. For one asset:

   | File | What it is |
   | --- | --- |
   | **SBOM** | CycloneDX, the components and versions from the latest full scan |
   | **VEX** | OpenVEX, whether each vulnerability affects it, from your triage |
   | **Technical report** | PDF with the open findings, grouped by fix |
   | **Audit evidence** | PDF for the chosen framework: scope, controls and every finding |

   For more than one asset, the same files come **consolidated**: an SBOM and a VEX covering every asset with a
   completed full scan (each with its own packages), and a consolidated audit evidence PDF with each asset, its
   coverage and its open risk (up to 500 assets).

The files of a single asset are the same exports you get in **Findings → More formats**.

## SBOM (CycloneDX 1.6)

The SBOM is built from the inventory every complete scan already stores; nothing is scanned again. It's available per
run and for the current state of a repository or image (taken from its latest full scan). It includes, for each
component:

- its package URL (purl) and version,
- its licenses, when Trivy provides them,
- whether it's a direct dependency of the product,
- for images, the operating system packages,

plus the tool, author and generation time. What Pitangus doesn't know (each package's supplier, per-component hashes)
isn't made up: it's left out, and the document says where its data comes from. It's valid against the official
CycloneDX schema and covers the baseline the CRA (Annex I) and the German BSI TR-03183-2 guideline ask for.

## VEX (OpenVEX)

A VEX answers "does this dependency vulnerability affect my product?". Pitangus already stores that decision with its
reason, author and date in triage, and maps it to standard statements, claiming nothing beyond what was decided:

| Triage | VEX status |
| --- | --- |
| Open, undecided | `under_investigation`: the scanner found it, nobody has confirmed it |
| In progress | `affected`, with the fix as the action |
| Accepted risk | `affected`, with the reason and expiry as the action |
| False positive | `not_affected`, with the reason as the impact statement |
| Fixed (by hand or because it stopped showing up) | `fixed` |

Only dependency advisories with an identifier (CVE, GHSA…) are included: first-party code isn't described with VEX.

## Malicious packages

OpenSSF `MAL-*` advisories (known malicious packages, through OSV) are flagged **Malicious**, critical and Act now,
with the actual fix: remove the package and rotate the secrets of every machine where it was installed. Never
"update to…".

## Frameworks

The audit evidence report maps the same technical evidence to the controls of the framework you choose. The mapping
is indicative.

| Region | Framework | What it maps |
| --- | --- | --- |
| International | SOC 2 Type II | CC3.2, CC7.1 and CC8.1 |
| International | ISO/IEC 27001:2022 | A.8.8, A.8.9, A.8.28 and A.8.29 |
| International | PCI DSS 4.0.1 | Requirements 6.2.4, 6.3.1, 6.3.2 (inventory) and 6.3.3 (patching within a month) |
| European Union | EU Cyber Resilience Act (CRA) | Annex I, part II (vulnerabilities, SBOM, testing) and article 14 |
| European Union | NIS2, Directive (EU) 2022/2555 | Art. 21(2) and technical annex: secure development, testing and vulnerabilities |
| European Union | DORA, Regulation (EU) 2022/2554 | Financial entities: ICT risk, testing and vulnerability management |
| European Union | GDPR, Art. 32 | Security of processing: the technical side of software that handles personal data |
| United States | NIST SSDF, SP 800-218 | Secure software development |
| United States | NIST CSF 2.0 | Identify and Protect: inventory, vulnerabilities, risk responses and secure development |
| United States | NIST SP 800-53 Rev. 5 | FedRAMP: vulnerability scanning, flaw remediation and developer testing |
| United States | HIPAA Security Rule | Healthcare: input for risk analysis and risk management |
| Latin America | Brazil: CMN Res. 4.893 / 5.274 | Continuous vulnerability management, testing and traceability |
| Latin America | Chile: Law 21.663 | Risk management, periodic review and a record of decisions |
| Latin America | Colombia: SFC, CE 007 of 2018 | Technical vulnerabilities, secure development and evidence for supervisors |
| Latin America | Mexico: CNBV, banks (CUB) and crowdfunding (IFC) | Vulnerability tests, classification and remediation |
| Latin America | Mexico: e-money institutions (IFPE) | Vulnerability scanning, remediation plan and code analysis before release |
| Latin America | Mexico: LFPDPPP, Art. 18 | Technical security measures for personal data |
| — | General | No framework: vulnerability management |

**What the audit evidence contains.** A concise PDF with scope, method, the findings and their status, approved
exceptions (accepted risks and false positives with their reason), the [remediation deadline](findings.md#remediation-deadlines)
policy with the overdue findings, and space for sign-offs. Generated from **Findings → More formats → Audit evidence**,
you can fill in the organization, who it's prepared for and by, the system, the period, how much per-finding detail
to include (all, critical and high only, or the table only) and whether to include exceptions. Everything is
optional.

## Images and the repositories they're built from

**Images** shows which repository each image is built from, read from its OCI labels or linked by hand by an
administrator (a manual link wins). A repository's evidence then brings the images built from it, and reports say
"built from org/repo @ commit". See [Scan container images](scanning-images.md).

## CRA kit (opt-in)

The EU Cyber Resilience Act requires manufacturers that sell products with digital elements in the EU to report
every vulnerability **actively exploited in their product**, from 11 September 2026: an early warning within 24 hours
of becoming aware, a notification within 72 hours, and a final report within 14 days of a corrective measure being
available. Reports go through ENISA's single reporting platform. **Pitangus never reports for you**: it tracks the
deadlines, prepares a draft and records who marked each stage as sent.

The kit is off by default and only makes sense if the CRA applies to you.

1. **Turn it on.** An administrator opens **Policies**, finds **We sell products with software in the EU (CRA)**,
   clicks **Turn on** and gives a reason, which is kept in the history. Turning it off hides the kit and keeps its
   data.
2. **Mark your products.** In **Compliance**, an administrator uses **Mark a product** to choose which repositories
   or images are products, with their marketed name and how long they're supported.
3. **Assess each KEV match.** When a CVE from the CISA KEV catalog shows up in a product, an event opens **to
   assess**, with no deadline running: KEV only says the CVE is exploited somewhere, and your product may not reach
   the vulnerable code. An administrator records either:
   - **Doesn't affect our product**, with a reason. The event closes and can be reopened.
   - **Actively exploited in our product**: there's reliable evidence that someone exploited it in your product.
     That moment is the awareness time, and the 24 h, 72 h and 14-day deadlines start from it. This can't be undone.
4. **Report and record.** Each event shows the time left per stage. **Copy draft** gives you a text to send through
   ENISA's platform; **Mark as sent** records who sent each stage and when.

A finding dismissed as a false positive in triage doesn't open an event. Events are computed on every scan, so a
product needs a completed full scan before anything can be assessed.

## Common errors

| What you see | Why | What to do |
| --- | --- | --- |
| "Needs a completed full scan" next to the SBOM | The asset has no finished full scan, or the last one was incomplete | Run a full scan and make sure every engine ran. |
| The SBOM has no supplier or hashes | Pitangus doesn't invent data it doesn't have | Add them from your build system if your auditor needs them. |
| The VEX lists a vulnerability as `under_investigation` | Nobody triaged it yet | Triage it in **Findings**. |
| "A consolidated report covers up to 500 assets" | The scope is too large | Narrow the scope. |
| The CRA kit doesn't appear | CRA reporting is off | An administrator turns it on in **Policies**. |

## Next steps

- [Findings, triage and remediation](findings.md).
- [Scan container images](scanning-images.md).
- [Threat modeling](threat-modeling.md): design-level evidence to go with the scans.
- [Security](security.md): how Pitangus protects your data.
