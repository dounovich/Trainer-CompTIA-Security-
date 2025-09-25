// Ajoutez ici vos 100 questions (domain: 'network' | 'threats' | 'identity' | 'crypto' | 'risk')
const QUESTIONS = [
  { q: "Quel est le but principal d'une attaque de phishing ?", choices: ["Voler des identifiants", "Arrêter un service", "Altérer le DNS", "Installer un pare-feu"], answer: 0, domain: "threats" },
  { q: "Quel protocole est sécurisé pour l'accès à distance ?", choices: ["Telnet", "SSH", "FTP", "HTTP"], answer: 1, domain: "network" },
  { q: "Quel algorithme est symétrique ?", choices: ["RSA", "AES", "ECC", "DSA"], answer: 1, domain: "crypto" },
  { q: "Quel principe consiste à donner le minimum de droits nécessaires ?", choices: ["Privilegium", "Need-to-know", "Principe du moindre privilège", "Séparation des tâches"], answer: 2, domain: "identity" },
  { q: "Quel document évalue l'impact et la probabilité d'un risque ?", choices: ["Plan de reprise", "Analyse de risque", "Rapport d'audit", "Procédure d'incident"], answer: 1, domain: "risk" },
  { q: "Un IDS est utilisé pour :", choices: ["Bloquer le trafic", "Surveiller et alerter", "Chiffrer les communications", "Gérer les clés"], answer: 1, domain: "network" }
];
