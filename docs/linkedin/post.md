Your scanner says "dependency X has CVE-Y". But can your code actually reach the vulnerable function?

That is the question I built Stubby to answer.

Stubby is an open-source tool that reads your lockfile, looks up known vulnerabilities on OSV.dev, and checks whether your project (and the packages that depend on the vulnerable one) can really reach the vulnerable code. The result is an OpenVEX document you can review, version and share, which is exactly the kind of statement regulations like the EU Cyber Resilience Act are starting to ask for.

Where the LLM comes in: advisories rarely say WHICH function is dangerous in a structured way. Stubby uses an LLM to read the public advisory text and the fix-commit diff and propose the vulnerable symbols. But the model only proposes. Every symbol must be backed by a verbatim quote from the advisory or the diff, or it is dropped. And only public advisory data is sent to the model, never your source code.

Then deterministic analysis takes over: imports, call sites, and a name graph inside the installed package to see whether the functions you use can lead to the vulnerable one.

Design principle: never give false comfort. "Not affected" requires cited evidence. When Stubby cannot rule something out, it says "inconclusive" and tells you why. A false "not affected" is treated as a release blocker, and the benchmark of real advisories fails if one appears.

Supports npm, Python, Java and PHP. It is an early release (v0.10) and the verdicts are drafts for human review, not guarantees.

pip install stubby-vex
https://github.com/jnascimentogcc/stubby

Feedback and benchmark cases (a real CVE, a small project, the expected verdict) are very welcome.

#OpenSource #DevSecOps #SupplyChainSecurity #VEX #SBOM #LLM #AppSec
