# kore-plugin-integrity (plugin d'intégrité des fichiers critiques)

## Ce que fait le plugin

Construit une base de référence sha256 des fichiers critiques et la compare à la demande, en signalant les fichiers modifiés, ajoutés ou supprimés. Le plugin ne fait que lire les fichiers et calculer les empreintes et métadonnées : il ne lit jamais le contenu, ne modifie pas les fichiers analysés, n'élève pas les privilèges et n'émet pas d'événements. depth_level=basic, lifecycle=lazy, protocole kore.plugin.v1.

Les méthodes de lecture déclarent system:read ; baseline, restore et schedule.set déclarent system:admin ; au niveau plugin, system:read + system:admin est déclaré (le niveau méthode ne fait que restreindre, jamais élargir).

## Points clés

- Seule dépendance externe : github.com/pengtang1024/kore/pkg/pluginapi v0.1.1 ; le reste est la bibliothèque standard.
- Ressources : memory_mb 6, cpu_quota 10 %, pids_max 16 ; le hachage en flux garde la mémoire résidente indépendante de la taille des fichiers.
- Méthodes : baseline, baseline.list, restore, check, status, verify_file, schedule.set, schedule.get (les tableaux complets de paramètres sont dans DETAIL.md ; les noms de méthodes et champs JSON sont indépendants de la langue).
- Alertes : file_removed et file_modified (critical), file_added et scan_incomplete (warning) ; renvoyées uniquement dans alerts[], jamais diffusées.

## Installation et vérification

Installez `integrity` depuis le marché de plugins ou importez dist/integrity-0.6.0.tar.gz produit par make dist. Vérifiez avec make check (gofmt, go vet, go test -timeout 200s).

---

简体中文原文见 [DETAIL.md](DETAIL.md)。
