# OpenCBAC-Firewall

Conception, développement et déploiement d’un pare-feu hôte sous Linux basé sur l’inspection d’état des connexions (CBAC) avec interface web, journalisation des événements, simulation d’attaques et mécanismes de défense

# Fonctionnalités

Gestion des règles (IP, ports, protocoles) 
Inspection d’état (NEW, ESTABLISHED, RELATED) 
Journalisation des connexions 

# Dashboard web :
trafic 
alertes 
gestion dynamique des règles

 
# Partie attaque
scan de ports 
tentative de connexion non autorisée 
flood simple
 
# Partie défense
blocage dynamique 
filtrage stateful 
limitation de connexions 
alertes 





# CBAC Shield

Application locale FastAPI pour administrer un pare-feu hote Linux base sur iptables, conntrack et une logique CBAC simplifiee.

## Demarrage local

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Interface: http://127.0.0.1:8000

Compte initial:

- utilisateur: `admin`
- mot de passe: `admin123`

## Mode iptables reel

Par defaut, CBAC Shield applique vraiment les regles avec `iptables`. Il doit etre lance sur Linux avec les privileges root. Si le programme est execute sur Windows, sans `sudo`, ou sans `iptables`, il refuse d'appliquer les regles au lieu de simuler.

```bash
sudo bash scripts/install.sh
sudo systemctl enable --now cbac-shield
```

## Lancer le web avec sudo

Sur Kali/Linux, l'interface web doit etre lancee avec les droits root si tu veux appliquer les regles depuis le navigateur.

Methode recommandee avec systemd:

```bash
sudo systemctl restart cbac-shield
sudo systemctl status cbac-shield
```

L'interface sera disponible sur:

```text
http://127.0.0.1:8000
```

Lancement manuel depuis le dossier installe:

```bash
cd /opt/cbac-shield
sudo env -u CBAC_DRY_RUN .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Si le projet est dans ton dossier utilisateur:

```bash
cd ~/CBAC-shield
sudo env -u CBAC_DRY_RUN .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Verification rapide:

```bash
sudo cbacctl status
sudo iptables -L INPUT -n --line-numbers
```

Le champ `Config` de `sudo cbacctl status` doit afficher:

```text
/etc/cbac-shield
```

Le tableau de bord web affiche aussi le dossier de configuration utilise. Si la CLI et le web n'affichent pas le meme dossier, reinstalle le wrapper CLI:

```bash
cd ~/CBAC-shield
git pull
sudo bash scripts/install.sh
sudo systemctl restart cbac-shield
```

Pour faire un test volontaire sans modifier iptables, active explicitement le mode dry-run:

```powershell
$env:CBAC_DRY_RUN = "true"
.\scripts\cbacctl.ps1 allow 22/tcp
```

## Commandes type ufw

En developpement Windows:

```powershell
$env:CBAC_DRY_RUN = "true"
.\scripts\cbacctl.ps1 status
.\scripts\cbacctl.ps1 allow 22/tcp
.\scripts\cbacctl.ps1 deny from 192.168.100.20
.\scripts\cbacctl.ps1 allow from 192.168.100.10 to any port 80 proto tcp
.\scripts\cbacctl.ps1 delete 1
.\scripts\cbacctl.ps1 reload
```

Apres installation Linux:

```bash
sudo cbacctl status
sudo cbacctl allow in 22/tcp
sudo cbacctl allow 22/tcp
sudo cbacctl deny in from 192.168.100.20
sudo cbacctl deny from 192.168.100.20
sudo cbacctl deny out to aerocash.app
sudo cbacctl allow out to aerocash.app
sudo cbacctl allow from 192.168.100.10 to any port 80 proto tcp
sudo cbacctl delete 1
sudo cbacctl reload
sudo cbacctl block 192.168.100.20 --reason "scan de ports" --duration 120
sudo cbacctl blocked
sudo cbacctl block-site aerocash.app --reason "site interdit"
sudo cbacctl blocked-sites
```

Commandes disponibles:

- `status` ou `rules`: afficher les regles numerotees.
- `allow ...`: ajouter une regle ACCEPT.
- `deny ...`: ajouter une regle DROP.
- `allow in ...` / `deny in ...`: ajouter une regle entrante explicite. Sans `in`, les regles `allow` et `deny` restent entrantes par defaut.
- `deny out to <domaine|ip>`: bloquer une connexion sortante, comme `ufw deny out to ...`.
- `allow out to <domaine|ip>`: retirer un blocage sortant.
- `delete <numero|id>`: supprimer une regle.
- `enable-rule <numero|id>` / `disable-rule <numero|id>`: activer ou desactiver une regle.
- `reload` ou `enable`: appliquer les regles CBAC dans iptables.
- `disable --yes`: vider les chaines et repasser les politiques en ACCEPT.
- `block <ip>` / `unblock <ip>` / `blocked`: gerer les IP bloquees.
- `block-site <domaine|ip>` / `unblock-site <id>` / `blocked-sites`: bloquer un site en sortie avec des regles `OUTPUT`.
- `logs --kind events` ou `logs --kind alerts`: consulter les journaux.
- `backups` / `restore <fichier>`: gerer les sauvegardes.

## Fonctionnalites

- Authentification administrateur avec session locale.
- Tableau de bord: etat, politique, regles actives, IP bloquees, alertes recentes.
- Creation, modification, activation, desactivation et suppression des regles INPUT.
- Application des regles CBAC de base: DROP par defaut, loopback, ESTABLISHED/RELATED, INVALID.
- Sauvegarde automatique de `rules.json` avant modification.
- Restauration des anciennes regles.
- Journalisation JSONL des evenements et alertes.
- Blocage manuel ou automatique d'adresses IP avec duree d'expiration.

## Fichiers importants

- `app/main.py`: routes FastAPI et interface web.
- `app/firewall_engine.py`: traduction des regles en commandes iptables.
- `app/rule_manager.py`: persistence JSON et sauvegardes.
- `app/defense_engine.py`: blocage d'IP et expiration.
- `config/rules.json`: regles personnalisees.
- `config/blocked_ips.json`: IP bloquees.
- `config/admin.json`: compte administrateur.
