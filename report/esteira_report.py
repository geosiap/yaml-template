#!/usr/bin/env python3
"""Report da esteira aprimorada: uma issue por ferramenta (job), deduplicada por fingerprint.

Para cada job que falhou no run:
  1. lê o artefato do job (``<job>-report``) e extrai os achados normalizados
     (regra/CVE + arquivo/pacote, sem número de linha);
  2. fingerprint = sha256 dos achados ordenados;
  3. procura issue aberta com as labels ``ci-failure`` + ``esteira:<job>``:
     - mesmo fingerprint  -> comenta "reincidência" (nenhum card novo);
     - fingerprint mudou  -> issue nova (label ``esteira:erro-novo``) com link para a anterior;
     - nenhuma aberta     -> issue nova;
  4. issue nova entra no board (GitHub Project V2) na coluna configurada.

Sem artefato (testes, ferramenta que quebrou antes de gerar relatório), o fingerprint
usa os nomes dos steps que falharam, lidos da API do run.
"""
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
SERVER = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
REPO = os.environ["GITHUB_REPOSITORY"]
OWNER = REPO.split("/")[0]
RUN_ID = os.environ["GITHUB_RUN_ID"]
RUN_ATTEMPT = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
REF_NAME = os.environ.get("GITHUB_REF_NAME", "")
SHA = os.environ.get("GITHUB_SHA", "")
ACTOR = os.environ.get("GITHUB_ACTOR", "")
RUN_TOKEN = os.environ["RUN_TOKEN"]          # github.token (actions: read)
APP_TOKEN = os.environ["APP_TOKEN"]          # token da GitHub App (issues + board)
NEEDS = json.loads(os.environ["NEEDS_JSON"])
ARTIFACTS_DIR = Path(os.environ.get("ARTIFACTS_DIR", "."))
BOARD_NUMBER = int(os.environ.get("BOARD_NUMBER", "33"))
STATUS_COLUMN = os.environ.get("STATUS_COLUMN", "Security issues")
ARTIFACT_MAP = json.loads(os.environ.get("ARTIFACT_MAP") or "{}")
DEFAULT_ARTIFACT_MAP = {"trivy": "trivy-iac-report"}  # nome fixo da action trivy
MAX_LIST = 30
RUN_URL = f"{SERVER}/{REPO}/actions/runs/{RUN_ID}"


# ── HTTP ─────────────────────────────────────────────────────────────────────

def call(method, path, token, body=None):
    url = path if path.startswith("http") else f"{API}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:500]
        raise RuntimeError(f"{method} {url} -> HTTP {e.code}: {detail}") from None


def graphql(query, variables=None):
    res = call("POST", "/graphql", APP_TOKEN, {"query": query, "variables": variables or {}})
    if res.get("errors"):
        raise RuntimeError(f"GraphQL: {res['errors']}")
    return res["data"]


# ── Parsers: cada um devolve um conjunto de achados "regra | alvo" ───────────

def load_json(path):
    try:
        return json.loads(path.read_text(errors="replace"))
    except Exception:
        return None


def p_semgrep(d):
    return {f"{r.get('check_id')} | {r.get('path')}" for r in (d or {}).get("results", [])}


def p_gitleaks(d):
    return {f"{f.get('RuleID')} | {f.get('File')} | {str(f.get('Commit', ''))[:12]}" for f in (d or [])}


def p_snyk(d):
    out = set()
    for proj in (d if isinstance(d, list) else [d or {}]):
        for v in proj.get("vulnerabilities", []) or []:
            out.add(f"{v.get('id')} | {v.get('packageName')} | {proj.get('displayTargetFile', '')}")
    return out


def p_phpstan(d):
    return {f"{m.get('message')} | {path}" for path, f in ((d or {}).get("files") or {}).items()
            for m in f.get("messages", [])}


def p_phpcs(d):
    return {f"{m.get('source')} | {path}" for path, f in ((d or {}).get("files") or {}).items()
            for m in f.get("messages", [])}


def p_rubocop(d):
    offs = [(f.get("path"), o) for f in (d or {}).get("files", []) for o in f.get("offenses", [])]
    graves = [(p, o) for p, o in offs if o.get("severity") in ("error", "fatal")]
    return {f"{o.get('cop_name')} | {p}" for p, o in (graves or offs)}


def p_brakeman(d):
    return {f"{w.get('check_name')}/{w.get('warning_type')} | {w.get('file')}" for w in (d or {}).get("warnings", [])}


def p_bandit(d):
    return {f"{r.get('test_id')} {r.get('test_name')} | {r.get('filename')}" for r in (d or {}).get("results", [])}


def p_pylint(d):
    return {f"{m.get('symbol')} | {m.get('path')}" for m in (d or []) if m.get("type") in ("error", "fatal", "warning")}


def p_hadolint(d):
    return {f"{i.get('code')} | {i.get('file')}" for i in (d or [])}


def p_rector(d):
    return {f"{r} | {f.get('file')}" for f in (d or {}).get("file_diffs", []) for r in f.get("applied_rectors", []) or ["?"]}


JSON_PARSERS = {
    "semgrep": p_semgrep, "gitleaks": p_gitleaks, "snyk": p_snyk, "phpstan": p_phpstan,
    "phpcs": p_phpcs, "rubocop": p_rubocop, "brakeman": p_brakeman, "bandit": p_bandit,
    "pylint": p_pylint, "hadolint": p_hadolint, "rector": p_rector,
}


def p_trivy_text(text):
    """Relatórios de tabela do trivy.
    config (IaC): cabeçalho "<arquivo> (dockerfile)" + linhas "DS-0002 (HIGH): ..." -> "DS-0002 | arquivo";
    image: linhas da tabela com CVE/GHSA -> "CVE-... | pacote" (linha de continuação herda o pacote)."""
    out, pkg, target = set(), "", ""
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^(\S.*) \((\w[\w-]*)\)$", s)
        if m:
            target = m.group(1)
            continue
        m = re.match(r"^((?:AVD-)?[A-Z]{2,4}-\d{4}) \((?:LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN)\):", s)
        if m:
            out.add(f"{m.group(1)} | {target}")
            continue
        ids = re.findall(r"\b(CVE-\d{4}-\d+|GHSA-[\w-]+)\b", line)
        if not ids:
            continue
        cells = [c.strip() for c in re.split(r"[│|]", line)]
        cells = [c for c in cells if c]
        if cells and not re.match(r"^(CVE|GHSA)-", cells[0]):
            pkg = cells[0]
        for i in ids:
            out.add(f"{i} | {pkg or target}")
    return out


def p_flake8_text(text):
    out = set()
    for line in text.splitlines():
        m = re.match(r"^(.+?):\d+:\d+: ([A-Z]+\d+)", line)
        if m:
            out.add(f"{m.group(2)} | {m.group(1)}")
    return out


def p_generic_text(text):
    """Fallback: linhas sem números (número de linha/coluna não entra no fingerprint)."""
    out = set()
    for line in text.splitlines():
        norm = re.sub(r"\s+", " ", re.sub(r"\d+", "#", line)).strip()
        if re.search(r"[A-Za-z]{3}", norm) and len(norm) < 300:
            out.add(norm)
    return out


def findings_from_artifact(job, art_dir):
    tool = next((t for t in JSON_PARSERS if job == t or job.startswith(t + "-")), None)
    found = set()
    for f in sorted(p for p in art_dir.rglob("*") if p.is_file()):
        if f.suffix == ".json" and tool:
            found |= JSON_PARSERS[tool](load_json(f))
            continue
        text = f.read_text(errors="replace")
        if job.startswith("trivy"):
            found |= p_trivy_text(text)
        elif job.startswith("flake8"):
            found |= p_flake8_text(text)
        else:
            found |= p_generic_text(text)
    # caminho absoluto do runner (/home/runner/work/<repo>/<repo>/) não entra no achado
    return {re.sub(r"/home/runner/work/[^/]+/[^/]+/", "", x) for x in found}


# ── Dados do run ─────────────────────────────────────────────────────────────

def run_jobs():
    jobs = call("GET", f"/repos/{REPO}/actions/runs/{RUN_ID}/attempts/{RUN_ATTEMPT}/jobs?per_page=100", RUN_TOKEN)
    out = {}
    for j in jobs.get("jobs", []):
        out[j["name"]] = j
        out.setdefault(j["name"].split(" / ")[-1], j)  # job de reusable workflow: "<caller> / <job>"
    return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def job_error_lines(job_info, limit=5):
    """Últimas linhas de erro do log do job (sem timestamp/ANSI/números), para quando não há artefato.
    O endpoint de logs redireciona para um storage que não aceita o header Authorization: segue sem ele."""
    if not job_info:
        return []
    req = urllib.request.Request(f"{API}/repos/{REPO}/actions/jobs/{job_info['id']}/logs", headers={
        "Authorization": f"Bearer {RUN_TOKEN}", "Accept": "application/vnd.github+json"})
    try:
        urllib.request.build_opener(_NoRedirect).open(req)
        return []
    except urllib.error.HTTPError as e:
        if e.code not in (301, 302, 303, 307, 308):
            print(f"    aviso: log do job indisponível (HTTP {e.code})")
            return []
        location = e.headers.get("Location")
    try:
        with urllib.request.urlopen(location) as r:
            text = r.read().decode(errors="replace")
    except Exception as e:  # noqa: BLE001 — log é complemento, nunca derruba o report
        print(f"    aviso: falha ao baixar log do job ({e})")
        return []
    picked = []
    for raw in text.splitlines():
        if "\x1b[36;1m" in raw:  # eco do script (não é saída)
            continue
        line = re.sub(r"\x1b\[[0-9;]*m", "", re.sub(r"^\S+Z ", "", raw)).strip()
        if not re.search(r"\b(ERROR|Error|error:|FATAL|Fatal)\b|##\[error\]", line):
            continue
        if "Process completed with exit code" in line:
            continue
        norm = re.sub(r"\d+", "#", line.replace("##[error]", "")).strip()[:200]
        if norm and norm not in picked:
            picked.append(norm)
    return picked[-limit:]


def run_artifacts():
    arts = call("GET", f"/repos/{REPO}/actions/runs/{RUN_ID}/artifacts?per_page=100", RUN_TOKEN)
    return {a["name"]: a for a in arts.get("artifacts", [])}


# ── Issues / board ───────────────────────────────────────────────────────────

LABEL_COLORS = {"ci-failure": "d73a4a", "esteira:erro-novo": "fbca04"}


def ensure_label(name):
    try:
        call("POST", f"/repos/{REPO}/labels", APP_TOKEN,
             {"name": name, "color": LABEL_COLORS.get(name, "5319e7"), "description": "Esteira aprimorada"})
    except RuntimeError as e:
        if "already_exists" not in str(e) and "HTTP 422" not in str(e):
            raise


def open_issues_for(job):
    q = f"/repos/{REPO}/issues?state=open&labels=ci-failure,esteira:{job}&per_page=100&sort=created&direction=desc"
    return [i for i in call("GET", q, APP_TOKEN) if "pull_request" not in i]


def fp_of(issue):
    m = re.search(r"<!-- esteira-fp:([0-9a-f]{64}) -->", issue.get("body") or "")
    return m.group(1) if m else None


def add_to_board(issue_node_id):
    data = graphql("""query($org:String!,$n:Int!){organization(login:$org){projectV2(number:$n){
        id field(name:"Status"){... on ProjectV2SingleSelectField{id options{id name}}}}}}""",
                   {"org": OWNER, "n": BOARD_NUMBER})
    proj = data["organization"]["projectV2"]
    if not proj:
        raise RuntimeError(f"sem acesso ao board #{BOARD_NUMBER} (verifique a GitHub App)")
    item = graphql("""mutation($p:ID!,$c:ID!){addProjectV2ItemById(input:{projectId:$p,contentId:$c}){item{id}}}""",
                   {"p": proj["id"], "c": issue_node_id})["addProjectV2ItemById"]["item"]["id"]
    field = proj.get("field") or {}
    opt = next((o["id"] for o in field.get("options", []) if o["name"] == STATUS_COLUMN), None)
    if field.get("id") and opt:
        graphql("""mutation($p:ID!,$i:ID!,$f:ID!,$o:String!){updateProjectV2ItemFieldValue(input:{
            projectId:$p,itemId:$i,fieldId:$f,value:{singleSelectOptionId:$o}}){projectV2Item{id}}}""",
                {"p": proj["id"], "i": item, "f": field["id"], "o": opt})
    else:
        print(f"  aviso: coluna '{STATUS_COLUMN}' não encontrada no board #{BOARD_NUMBER}")
    return item


def findings_block(findings):
    lst = sorted(findings)
    shown = "\n".join(lst[:MAX_LIST])
    extra = f"\n… e mais {len(lst) - MAX_LIST} (lista completa no artefato)" if len(lst) > MAX_LIST else ""
    return f"```\n{shown}{extra}\n```" if lst else "_(sem achados legíveis — ver log do job)_"


def context_table(job, job_info, artifact, n_findings, fp):
    job_url = (job_info or {}).get("html_url", RUN_URL)
    art = f"[{artifact['name']}]({RUN_URL}/artifacts/{artifact['id']})" if artifact else "—"
    return (f"| Item | Valor |\n|---|---|\n| **Job** | [`{job}`]({job_url}) |\n| **Branch** | `{REF_NAME}` |\n"
            f"| **Commit** | `{SHA[:12]}` |\n| **Autor** | @{ACTOR} |\n| **Run** | [#{RUN_ID}]({RUN_URL}) |\n"
            f"| **Artefato** | {art} |\n| **Achados** | {n_findings} |\n| **Fingerprint** | `{fp[:12]}` |")


def handle(job, job_info, artifact, findings, source):
    fp = hashlib.sha256("\n".join(sorted(findings)).encode()).hexdigest()
    label = f"esteira:{job}"
    ensure_label(label)
    existing = open_issues_for(job)
    same = next((i for i in existing if fp_of(i) == fp), None)
    table = context_table(job, job_info, artifact, len(findings), fp)

    if same:
        call("POST", f"/repos/{REPO}/issues/{same['number']}/comments", APP_TOKEN, {"body":
             f"🔁 **Reincidência** — mesmos achados no run [#{RUN_ID}]({RUN_URL}) "
             f"(branch `{REF_NAME}`, commit `{SHA[:12]}`).\n\n{table}"})
        print(f"  {job}: reincidência -> comentado em #{same['number']}")
        return

    previous = existing[0] if existing else None
    labels = ["ci-failure", label] + (["esteira:erro-novo"] if previous else [])
    if previous:
        ensure_label("esteira:erro-novo")
    job_url = (job_info or {}).get("html_url", RUN_URL)
    next_step = ("1. Baixe o artefato e veja o detalhe de cada achado.\n" if artifact else
                 f"1. Sem relatório: abra o [log do job]({job_url}). Normalmente é erro de execução ou de "
                 f"configuração da ferramenta (token, versão, config), e não achado no código.\n")
    title = f"🚨 [{job}] {len(findings)} achado(s) na esteira — {REPO.split('/')[1]}"
    prev_txt = (f"\n> ⚠️ **Erro novo**: os achados de `{job}` mudaram desde #{previous['number']} "
                f"(fingerprint `{(fp_of(previous) or '?')[:12]}` → `{fp[:12]}`).\n") if previous else ""
    body = (f"## 🚨 `{job}` falhou na esteira\n{prev_txt}\n{table}\n\n### Achados ({source})\n"
            f"{findings_block(findings)}\n\n### Próximos passos\n"
            f"{next_step}"
            f"2. Corrija ou justifique; a esteira **não bloqueia** o deploy.\n"
            f"3. Enquanto os achados forem os mesmos, novos runs só comentam aqui.\n\n"
            f"---\n> Gerado automaticamente pela esteira aprimorada (geosiap/yaml-template/report)\n"
            f"<!-- esteira-fp:{fp} -->")
    issue = call("POST", f"/repos/{REPO}/issues", APP_TOKEN, {"title": title, "body": body, "labels": labels})
    print(f"  {job}: issue nova #{issue['number']}" + (f" (substitui #{previous['number']})" if previous else ""))
    if previous:
        call("POST", f"/repos/{REPO}/issues/{previous['number']}/comments", APP_TOKEN, {"body":
             f"🔀 Os achados de `{job}` mudaram no run [#{RUN_ID}]({RUN_URL}) — registrado em #{issue['number']}."})
    try:
        add_to_board(issue["node_id"])
        print(f"    card adicionado ao board #{BOARD_NUMBER} ('{STATUS_COLUMN}')")
    except RuntimeError as e:
        print(f"    ERRO ao adicionar no board: {e}")


def main():
    failed = [j for j, v in NEEDS.items() if v.get("result") == "failure"]
    if not failed:
        print("Nenhuma verificação falhou — nada a registrar.")
        return 0
    print(f"Jobs com falha: {', '.join(failed)}")
    jobs, artifacts = run_jobs(), run_artifacts()
    ensure_label("ci-failure")
    errors = 0
    units = []  # (job lógico, info do job na API, nome do artefato)
    for job in failed:
        art_name = ARTIFACT_MAP.get(job) or DEFAULT_ARTIFACT_MAP.get(job) or f"{job}-report"
        # job em matrix (ex.: trivy-image por imagem): jobs "<job> (<perna>)" na API + artefatos "<job>-<perna>-report"
        legs = [(a[len(job) + 1:-len("-report")], a) for a in sorted(artifacts)
                if a.startswith(f"{job}-") and a.endswith("-report") and a != art_name]
        legs = [(leg, a) for leg, a in legs if f"{job} ({leg})" in jobs]
        if art_name not in artifacts and legs:
            for leg, leg_art in legs:
                info = jobs[f"{job} ({leg})"]
                if info.get("conclusion") != "failure":
                    continue
                units.append((f"{job}-{leg}", info, leg_art))
        else:
            units.append((job, jobs.get(job), art_name))
    for job, info, art_name in units:
        art_dir = ARTIFACTS_DIR / art_name
        findings, source = set(), "artefato"
        if art_dir.is_dir():
            findings = findings_from_artifact(job, art_dir)
        if not findings:
            info = info or {}
            steps = [s["name"] for s in info.get("steps", []) if s.get("conclusion") == "failure"]
            errs = job_error_lines(info)
            findings = ({f"step falhou: {s}" for s in steps} | {f"erro: {e}" for e in errs}) or {"job falhou (sem detalhe)"}
            source = "log do job — sem artefato legível"
        try:
            handle(job, info, artifacts.get(art_name), findings, source)
        except RuntimeError as e:
            errors += 1
            print(f"  {job}: ERRO — {e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
