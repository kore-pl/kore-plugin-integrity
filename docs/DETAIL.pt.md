# kore-plugin-integrity (plugin de integridade de arquivos críticos)

## O que faz

Cria uma linha de base sha256 de arquivos críticos e os compara sob demanda, relatando arquivos modificados, adicionados ou removidos. O plugin apenas lê arquivos e calcula hashes e metadados: nunca lê conteúdos, não modifica arquivos verificados, não eleva privilégios e não emite eventos. depth_level=basic, lifecycle=lazy, protocolo kore.plugin.v1.

Métodos de leitura declaram system:read; baseline, restore e schedule.set declaram system:admin; no nível do plugin, system:read + system:admin (o nível de método apenas restringe, nunca amplia).

## Pontos-chave

- Única dependência externa: github.com/pengtang1024/kore/pkg/pluginapi v0.1.1; o restante é a biblioteca padrão.
- Recursos: memory_mb 6, cpu_quota 10%, pids_max 16; a hashagem em fluxo mantém a memória residente independente do tamanho do arquivo.
- Métodos: baseline, baseline.list, restore, check, status, verify_file, schedule.set, schedule.get (as tabelas completas de parâmetros estão em DETAIL.md; nomes de métodos e campos JSON são neutros quanto ao idioma).
- Alertas: file_removed e file_modified (critical), file_added e scan_incomplete (warning); retornados apenas em alerts[], nunca enviados externamente.

## Instalação e verificação

Instale `integrity` no mercado de plugins ou importe dist/integrity-0.6.0.tar.gz gerado por make dist. Verifique com make check (gofmt, go vet, go test -timeout 200s).

---

简体中文原文见 [DETAIL.md](DETAIL.md)。
