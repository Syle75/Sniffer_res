# Sniffer Réseau en Python (RAW Sockets)

Ce projet est un **sniffer de paquets réseau** écrit en Python. Il capture les trames IP passant par l'interface réseau de la machine et affiche les informations suivantes :
- Adresse IP source et destination
- Protocole utilisé (TCP, UDP, ICMP)
- Ports source et destination (pour TCP et UDP)

> Ce sniffer fonctionne uniquement sous **Linux** grâce à l’utilisation de `AF_PACKET`.

---

## Technologies utilisées

- Python 3
- `socket` (module standard)
- Sockets RAW (`AF_PACKET`) pour la capture bas niveau

---

## Installation et exécution

### 1. Cloner le projet

git clone https://github.com/Syle75/Sniffer_res.git
cd Sniffer_res

2. Lancer le sniffer

sudo python3 sniffer.py

    L'exécution en sudo est obligatoire pour pouvoir accéder aux sockets bruts.

3. Générer du trafic réseau

On peut ouvrir un site web ou exécuter une commande comme :

ping 8.8.8.8

4. Exemple de sortie

📦 192.168.1.42:56534 -> 8.8.8.8:53 | Protocole : UDP
📦 192.168.1.42 -> 192.168.1.254 | Protocole : ICMP
📦 192.168.1.42:443 -> 192.168.1.15:55678 | Protocole : TCP

🧠 Compétence acquise

    Utilisation de sockets bas niveau (AF_PACKET) sous Linux

    Décodage d’en-têtes Ethernet, IP, TCP/UDP

    Distinction des protocoles ICMP, UDP, TCP

    Affichage d’informations réseau brutes utiles en cybersécurité ou analyse de trafic

✅ Pré-requis

    Linux

    Python 3

    Connexion Internet locale pour générer du trafic

    Interface réseau active (ex: wlo2, eth0, etc.)

    Ce sniffer ne filtre pas encore les paquets ni ne sauvegarde les données : il affiche simplement les informations réseau en temps réel. Il est destiné à l'apprentissage de la cybersécurité et des réseaux TCP/IP.

    LYES HADBI

    Étudiant passionné par la cybersécurité et les réseaux.
    Ce projet fait partie de ma montée en compétences dans ce domaine.