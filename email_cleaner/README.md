# Email Cleaner

Application Flask + SocketIO pour nettoyer Gmail par mots-clés et pièces jointes.

## Déploiement sur Render ou Railway

1. Crée un projet Python.
2. Pousse ce repo sur GitHub.
3. Ajoute ton `client_secret.json`.
4. Configure l’URI de redirection OAuth sur Google Cloud : 
   `https://<ton-app>.onrender.com/oauth2callback` ou l’URL Railway.
5. Render / Railway détecte `requirements.txt`, `runtime.txt` et `Procfile`.
6. Déploie et accède à l'URL publique.
